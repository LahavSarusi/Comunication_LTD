import { z } from 'zod'

// Client-side validation is for user experience only - the server validates
// everything again and is the real security boundary.

export const USERNAME_PATTERN = /^[a-z0-9_]{3,30}$/

// Printable ASCII punctuation, same definition as the server.
const SPECIAL_CHAR_PATTERN = /[!-/:-@[-`{-~]/

/**
 * Password rules built from the policy the server loaded from
 * backend/config/password-policy.json, so the form always matches the server.
 */
export function getPasswordRules({ minLength, complexity }) {
  return [
    {
      id: 'length',
      label: `At least ${minLength} characters`,
      message: `Password must be at least ${minLength} characters`,
      test: (password) => password.length >= minLength,
    },
    complexity.uppercase && {
      id: 'uppercase',
      label: 'An uppercase letter (A-Z)',
      message: 'Password must contain an uppercase letter (A-Z)',
      test: (password) => /[A-Z]/.test(password),
    },
    complexity.lowercase && {
      id: 'lowercase',
      label: 'A lowercase letter (a-z)',
      message: 'Password must contain a lowercase letter (a-z)',
      test: (password) => /[a-z]/.test(password),
    },
    complexity.digits && {
      id: 'digits',
      label: 'A digit (0-9)',
      message: 'Password must contain a digit (0-9)',
      test: (password) => /[0-9]/.test(password),
    },
    complexity.specialChars && {
      id: 'specialChars',
      label: 'A special character (e.g. ! @ # $ %)',
      message: 'Password must contain a special character (e.g. ! @ # $ %)',
      test: (password) => SPECIAL_CHAR_PATTERN.test(password),
    },
  ].filter(Boolean)
}

export function buildRegisterSchema(policy) {
  let password = z.string().max(policy.maxLength, `Password must be at most ${policy.maxLength} characters`)
  for (const rule of getPasswordRules(policy)) {
    password = password.refine(rule.test, rule.message)
  }

  return z
    .object({
      username: z
        .string()
        .trim()
        .toLowerCase()
        .regex(USERNAME_PATTERN, 'Username must be 3-30 characters: letters, digits or underscore'),
      email: z
        .string()
        .trim()
        .toLowerCase()
        .max(254, 'Email is too long')
        .pipe(z.email('Please enter a valid email address')),
      password,
      confirmPassword: z.string(),
    })
    .superRefine(({ username, password, confirmPassword }, ctx) => {
      if (password !== confirmPassword) {
        ctx.addIssue({ code: 'custom', path: ['confirmPassword'], message: 'Passwords do not match' })
      }
      if (USERNAME_PATTERN.test(username) && password.toLowerCase().includes(username)) {
        ctx.addIssue({ code: 'custom', path: ['password'], message: 'Password must not contain your username' })
      }
    })
}
