import { NextResponse } from "next/server";
import {
  defaultLabelForProvider,
  getBankCredentials,
  getBankCredentialMeta,
  saveBankCredentials,
} from "@/server/db/queries/bank-credentials";
import {
  BANK_PROVIDERS,
  normalizeBankProvider,
  type BankProviderInfo,
} from "@/lib/types";
import { getWorkspaceIdFromRequest } from "@/server/lib/workspace-context";

function normalizeCredentials(
  credentials: Record<string, string>,
  info: BankProviderInfo
): Record<string, string> {
  const normalized: Record<string, string> = {};
  for (const field of info.credentialFields) {
    const raw = credentials[field.key] ?? "";
    const trimmed = raw.trim();
    normalized[field.key] = field.numeric ? trimmed.replace(/\D/g, "") : trimmed;
  }

  for (const [key, value] of Object.entries(credentials)) {
    if (!(key in normalized)) normalized[key] = value;
  }

  return normalized;
}

function validateCredentials(
  credentials: Record<string, string>,
  info: BankProviderInfo
): string | null {
  for (const field of info.credentialFields) {
    const value = credentials[field.key]?.trim() ?? "";
    if (!value) return `Missing required field: ${field.label}`;
    if (field.exactLength != null && value.length !== field.exactLength) {
      return `${field.label} must be exactly ${field.exactLength} characters.`;
    }
    if (field.maxLength != null && value.length > field.maxLength) {
      return `${field.label} must be ${field.maxLength} characters or fewer.`;
    }
    if (field.numeric && !/^\d+$/.test(value)) {
      return `${field.label} must contain digits only.`;
    }
  }
  return null;
}

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
  if (!info) {
    return NextResponse.json(
      { success: false, message: `Unsupported provider: ${body.provider}` },
      { status: 400 }
    );
  }

  const passwordKeys =
    info.credentialFields.filter((f) => f.type === "password").map((f) => f.key);

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

  const merged = normalizeCredentials(body.credentials, info);
  for (const key of passwordKeys) {
    if (!merged[key] || merged[key].trim() === "") {
      if (existing && existing[key]) {
        merged[key] = existing[key];
      }
    }
  }

  const validationError = validateCredentials(merged, info);
  if (validationError) {
    return NextResponse.json(
      { success: false, message: validationError },
      { status: 400 }
    );
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
