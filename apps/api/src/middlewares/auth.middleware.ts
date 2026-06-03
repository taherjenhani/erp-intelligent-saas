import { FastifyReply, FastifyRequest } from "fastify";
import { prisma } from "../lib/prisma";
import type { Role, SessionStatus } from "@prisma/client";

/**
 * Contexte ajouté à `request.auth` lorsqu’un utilisateur est authentifié.
 */
export type AuthContext = {
  userId: string;
  email: string;
  role: Role;
  sessionId: string;
  storeIds: string[];
};

/**
 * Middleware de protection des routes.
 * - Vérifie la validité du JWT d’accès (signature, expiration).
 * - Charge la session en base et s’assure qu’elle est ACTIVE et non expirée.
 * - Injecte dans `request.auth` les informations utilisateur.
 */
export async function requireAuth(
  request: FastifyRequest,
  reply: FastifyReply
) {
  try {
    // Vérifie et décode le JWT d’accès
    const payload = await request.jwtVerify<{
      sub: string;
      email: string;
      role: Role;
      sessionId: string;
      storeIds: string[];
    }>();

    // On récupère la session correspondante dans la BD
    const session = await prisma.session.findUnique({
      where: { id: payload.sessionId },
      select: {
        status: true,
        expiresAt: true,
        id: true,
      },
    });

    // On vérifie que la session existe
    if (!session) {
      return reply.status(401).send({
        success: false,
        message: "Session introuvable",
      });
    }

    // On vérifie que la session est ACTIVE
    if (session.status !== "ACTIVE") {
      return reply.status(401).send({
        success: false,
        message: "Session révoquée",
      });
    }

    // On vérifie l’expiration de session
    if (session.expiresAt && session.expiresAt < new Date()) {
      return reply.status(401).send({
        success: false,
        message: "Session expirée",
      });
    }

    // Si tout va bien, on expose les infos auth sur la requête
    request.auth = {
      userId: payload.sub,
      email: payload.email,
      role: payload.role,
      sessionId: payload.sessionId,
      storeIds: payload.storeIds ?? [],
    };
  } catch {
    // JWT invalide ou manquant
    return reply.status(401).send({
      success: false,
      message: "Unauthorized",
    });
  }
}