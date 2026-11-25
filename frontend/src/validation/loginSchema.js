import { z } from 'zod'

// Same username allowlist as the server (backend/src/validation/userSchemas.js).
const USERNAME_PATTERN = /^[a-z0-9_]{3,30}$/

/**
 * Client-side checks only improve usability; the server validates everything again.
 * The password is not checked against the complexity rules at login: it only has
 * to match the stored hash. It is never trimmed or altered.
 */
export const loginSchema = z.object({
  username: z
    .string()
    .trim()
    .toLowerCase()
    .min(1, 'Username is required')
    .regex(USERNAME_PATTERN, 'Username must be 3-30 characters: letters, digits or underscore'),
  password: z.string().min(1, 'Password is required').max(1024, 'Password is too long'),
})
