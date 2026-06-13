import { NextResponse } from "next/server";
import {
  defaultLabelForProvider,
  getBankCredentials,
  getBankCredentialMeta,
  saveBankCredentials,
} from "@/server/db/queries/bank-credentials";
import { BANK_PROVIDERS, normalizeBankProvider } from "@/lib/types";
import { getWorkspaceIdFromRequest } from "@/server/lib/workspace-context";

export async function POST(request: Request) {
  const workspaceId = getWorkspaceIdFromRequest(request);
  const body = (await request.json()) as {
    provider: string;
    credentials: Record<string, string>;
    label?: string;
    credentialId?: number;
    requiresManualTwoFactor?: boolean;
  };

  if (!body.provider || !body.credentials) {
    return NextResponse.json(
      { success: false, message: "Missing provider or credentials" },
      { status: 400 }
    );
  }

  const provider = normalizeBankProvider(body.provider);
  if (!provider) {
    return NextResponse.json(
      { success: false, message: `Unsupported provider: ${body.provider}` },
      { status: 400 }
    );
  }

  const info = BANK_PROVIDERS.find((b) => b.id === provider);
  const passwordKeys =
    info?.credentialFields.filter((f) => f.type === "password").map((f) => f.key) ?? [];

  const credentialId = body.credentialId;
  const existing =
    credentialId != null
      ? getBankCredentials(workspaceId, credentialId)
      : null;

  if (credentialId != null && !getBankCredentialMeta(workspaceId, credentialId)) {
    return NextResponse.json(
      { success: false, message: "Credential not found" },
      { status: 404 }
    );
  }

  const merged: Record<string, string> = { ...body.credentials };
  for (const key of passwordKeys) {
    if (!merged[key] || merged[key].trim() === "") {
      if (existing && existing[key]) {
        merged[key] = existing[key];
      }
    }
  }

  for (const field of info?.credentialFields ?? []) {
    const value = merged[field.key]?.trim();
    if (!value) {
      return NextResponse.json(
        { success: false, message: `Missing required field: ${field.label}` },
        { status: 400 }
      );
    }
    if (field.exactLength != null && value.length !== field.exactLength) {
      return NextResponse.json(
        {
          success: false,
          message: `${field.label} must be exactly ${field.exactLength} digits`,
        },
        { status: 400 }
      );
    }
  }

  if (existing?.otpLongTermToken && !merged.otpLongTermToken) {
    merged.otpLongTermToken = existing.otpLongTermToken;
  }

  const label =
    body.label?.trim() ||
    (credentialId != null
      ? getBankCredentialMeta(workspaceId, credentialId)?.label
      : defaultLabelForProvider(workspaceId, provider)) ||
    defaultLabelForProvider(workspaceId, provider);

  try {
    const id = saveBankCredentials(workspaceId, provider, merged, {
      credentialId,
      label,
      requiresManualTwoFactor: body.requiresManualTwoFactor,
    });
    return NextResponse.json({ success: true, credentialId: id });
  } catch (err) {
    const message =
      err instanceof Error ? err.message : "Failed to save credentials";
    if (/UNIQUE constraint/i.test(message)) {
      return NextResponse.json(
        {
          success: false,
          message: "An account with this label already exists for this bank.",
        },
        { status: 409 }
      );
    }
    throw err;
  }
}
