import { type NextFunction, type Request, type Response } from "express";
import * as jose from "jose";
import { UnauthorizedError } from "./errors";

const ALLOWED_IDENTITIES = process.env.ALLOWED_IDENTITIES?.split(",")
    .map((identity) => identity.trim().toLowerCase())
    .filter(Boolean);

const getAllowedIdentities = () => {
  if (!ALLOWED_IDENTITIES) return null;
  return ALLOWED_IDENTITIES.length > 0 ? new Set(ALLOWED_IDENTITIES) : null;
};

export const isIdentityAllowed = (identity?: string | null) => {
  const allowedIdentities = getAllowedIdentities();
  const identityNormalized = identity?.trim().toLowerCase();
  if (!allowedIdentities) return true;
  if (!identityNormalized) return false;
  return allowedIdentities.has(identityNormalized);
};

export const verifyToken = async (idToken: string) => {
  const JWKS = jose.createRemoteJWKSet(
    new URL("https://www.googleapis.com/oauth2/v3/certs"),
  );

  try {
    const { payload } = await jose.jwtVerify(idToken, JWKS, {
      issuer: "https://accounts.google.com",
      audience: process.env.GOOGLE_CLIENT_ID,
    });

    return payload;
  } catch  (e) {
    console.error(e);
    return null;
  }
};

// Sesión propia: la cookie (firmada con COOKIE_SECRET) guarda email/sub/iat al entrar y vale SESSION_MAX_DAYS
// (30 por defecto). Antes se reverificaba el id_token de Google en cada petición y ese token caduca a la hora,
// así que cada hora había que volver a pasar por Google (y su verificación en dos pasos).
const SESSION_MAX_MS = Number(process.env.SESSION_MAX_DAYS || 30) * 24 * 60 * 60 * 1000;

export const authenticated = async (req: Request, res: Response, next: NextFunction) => {
  const idToken = req.session?.id_token;
  if (!idToken) throw new UnauthorizedError();

  const auth = req.session?.auth as { email?: string; iat?: number } | undefined;
  if (auth?.iat && Date.now() - auth.iat < SESSION_MAX_MS) {
    if (!isIdentityAllowed(auth.email)) {
      throw new UnauthorizedError("Account is not in the allowlist", "account_not_allowed");
    }
    return next();
  }

  // Sin sesión propia (cookie anterior al cambio) o caducada: verificar el id_token de Google como antes.

  const payload = await verifyToken(idToken);
  if (!payload) throw new UnauthorizedError();
  if (!payload.exp) throw new UnauthorizedError();

  if (new Date(payload.exp * 1000) < new Date()) {
    throw new UnauthorizedError();
  }

  const email = (payload as { email?: string }).email;
  if (!isIdentityAllowed(email)) {
    throw new UnauthorizedError("Account is not in the allowlist", "account_not_allowed");
  }

  next();
};
