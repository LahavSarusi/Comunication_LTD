import { z } from 'zod'
import { USERNAME_PATTERN, getPasswordRules } from './registerSchema.js'

// Client-side validation is for user experience only - the server validates
// everything again (including the dictionary and the password history, which
// are never sent to the browser) and is the real security boundary.

/**
 * Change-password form rules, built from the same server policy and the same
 * rule list as the registration form, so both screens always agree.
 */
export function buildChangePasswordSchema(policy) {
  let newPassword = z.string().max(policy.maxLength, `New password must be at most ${policy.maxLength} characters`)
  for (const rule of getPasswordRules(policy)) {
    newPassword = newPassword.refine(rule.test, rule.message.replace(/^Password/, 'New password'))
  }

  return z
    .object({
      username: z
        .string()
        .trim()
        .toLowerCase()
        .regex(USERNAME_PATTERN, 'Username must be 3-30 characters: letters, digits or underscore'),
      // Not checked against the policy: it may be older than the current policy.
      currentPassword: z
        .string()
        .min(1, 'Current password is required')
        .max(policy.maxLength, `Current password must be at most ${policy.maxLength} characters`),
      newPassword,
      confirmPassword: z.string(),
    })
    .superRefine(({ username, currentPassword, newPassword, confirmPassword }, ctx) => {
      if (newPassword !== confirmPassword) {
        ctx.addIssue({ code: 'custom', path: ['confirmPassword'], message: 'Passwords do not match' })
      }
      if (USERNAME_PATTERN.test(username) && newPassword.toLowerCase().includes(username)) {
        ctx.addIssue({ code: 'custom', path: ['newPassword'], message: 'New password must not contain your username' })
      }
      if (currentPassword && newPassword === currentPassword) {
        ctx.addIssue({
          code: 'custom',
          path: ['newPassword'],
          message: 'New password must be different from your current password',
        })
      }
    })
}
