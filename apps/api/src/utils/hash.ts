import bcrypt from "bcrypt";
import { env } from "../config/env";

const SALT_ROUNDS = 12;

export async function hashPassword(password: string): Promise<string> {
  return bcrypt.hash(password + env.PASSWORD_PEPPER, SALT_ROUNDS);
}

export async function verifyPassword(
  password: string,
  hashedPassword: string
): Promise<boolean> {
  return bcrypt.compare(password + env.PASSWORD_PEPPER, hashedPassword);
}