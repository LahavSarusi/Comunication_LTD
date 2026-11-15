import { useEffect, useMemo, useState } from 'react'
import { z } from 'zod'
import { changePassword, getPasswordPolicy, parseApiError } from '../../api/client.js'
import { buildChangePasswordSchema } from '../../validation/changePasswordSchema.js'
import { getPasswordRules } from '../../validation/registerSchema.js'
// Same card, fields, checklist, alerts and buttons as the Register screen.
import '../Register/Register.css'

const EMPTY_FORM = { username: '', currentPassword: '', newPassword: '', confirmPassword: '' }

// All user/server text is rendered as plain JSX text, which React escapes.
// dangerouslySetInnerHTML is intentionally never used (XSS prevention).
function FieldErrors({ id, errors }) {
  if (!errors?.length) return null
  return (
    <ul id={id} className="field-errors">
      {errors.map((message) => (
        <li key={message}>{message}</li>
      ))}
    </ul>
  )
}

function ChangePassword() {
  const [policy, setPolicy] = useState(null)
  const [policyError, setPolicyError] = useState('')
  const [policyRequest, setPolicyRequest] = useState(0)
  const [form, setForm] = useState(EMPTY_FORM)
  const [fieldErrors, setFieldErrors] = useState({})
  const [serverError, setServerError] = useState('')
  const [submitting, setSubmitting] = useState(false)
  const [showPasswords, setShowPasswords] = useState(false)
  const [changed, setChanged] = useState(false)

  // Password rules come from the server (backend/config/password-policy.json).
  useEffect(() => {
    const controller = new AbortController()
    getPasswordPolicy({ signal: controller.signal })
      .then(setPolicy)
      .catch((error) => {
        if (!controller.signal.aborted) setPolicyError(parseApiError(error).message)
      })
    return () => controller.abort()
  }, [policyRequest])

  const rules = useMemo(() => (policy ? getPasswordRules(policy) : []), [policy])
  const schema = useMemo(() => (policy ? buildChangePasswordSchema(policy) : null), [policy])

  function retryPolicy() {
    setPolicyError('')
    setPolicyRequest((count) => count + 1)
  }

  function handleChange(event) {
    const { name, value } = event.target
    setForm((previous) => ({ ...previous, [name]: value }))
    setFieldErrors((previous) => ({ ...previous, [name]: undefined }))
    setServerError('')
  }

  async function handleSubmit(event) {
    event.preventDefault()
    if (!schema || submitting) return

    const result = schema.safeParse(form)
    if (!result.success) {
      setFieldErrors(z.flattenError(result.error).fieldErrors)
      return
    }

    setSubmitting(true)
    setServerError('')
    try {
      const { username, currentPassword, newPassword } = result.data
      await changePassword({ username, currentPassword, newPassword })
      // Never keep the passwords in memory longer than needed.
      setForm(EMPTY_FORM)
      setFieldErrors({})
      setShowPasswords(false)
      setChanged(true)
    } catch (error) {
      const { message, fieldErrors: serverFieldErrors } = parseApiError(error)
      setServerError(message)
      setFieldErrors(serverFieldErrors)
      // After wrong credentials the current password is cleared; the user retypes it.
      if (error.response?.status === 401) {
        setForm((previous) => ({ ...previous, currentPassword: '' }))
      }
    } finally {
      setSubmitting(false)
    }
  }

  if (changed) {
    return (
      <section className="register-card" aria-live="polite">
        <h1 className="register-title">Password changed</h1>
        <p className="register-success">Your password was updated. Use the new password from now on.</p>
        <button type="button" className="btn-primary" onClick={() => setChanged(false)}>
          Change another password
        </button>
      </section>
    )
  }

  const errorProps = (name) => ({
    'aria-invalid': fieldErrors[name]?.length ? true : undefined,
    'aria-describedby': fieldErrors[name]?.length ? `${name}-errors` : undefined,
  })
  const passwordType = showPasswords ? 'text' : 'password'

  return (
    <section className="register-card">
      <h1 className="register-title">Change your password</h1>
      <p className="register-subtitle">Enter your current password, then choose a new one.</p>

      {policyError && (
        <div className="alert alert-error" role="alert">
          <span>{policyError}</span>
          <button type="button" className="btn-link" onClick={retryPolicy}>
            Try again
          </button>
        </div>
      )}

      {serverError && (
        <div className="alert alert-error" role="alert">
          {serverError}
        </div>
      )}

      <form className="register-form" onSubmit={handleSubmit} noValidate>
        <div className="field">
          <label htmlFor="username">Username</label>
          <input
            id="username"
            name="username"
            type="text"
            value={form.username}
            onChange={handleChange}
            autoComplete="username"
            autoCapitalize="none"
            spellCheck={false}
            maxLength={30}
            required
            {...errorProps('username')}
          />
          <FieldErrors id="username-errors" errors={fieldErrors.username} />
        </div>

        <div className="field">
          <div className="field-label-row">
            <label htmlFor="currentPassword">Current password</label>
            <button
              type="button"
              className="btn-link"
              onClick={() => setShowPasswords((visible) => !visible)}
              aria-pressed={showPasswords}
              aria-controls="currentPassword newPassword confirmPassword"
            >
              {showPasswords ? 'Hide' : 'Show'}
            </button>
          </div>
          <input
            id="currentPassword"
            name="currentPassword"
            type={passwordType}
            value={form.currentPassword}
            onChange={handleChange}
            autoComplete="current-password"
            maxLength={policy?.maxLength}
            required
            {...errorProps('currentPassword')}
          />
          <FieldErrors id="currentPassword-errors" errors={fieldErrors.currentPassword} />
        </div>

        <div className="field">
          <label htmlFor="newPassword">New password</label>
          <input
            id="newPassword"
            name="newPassword"
            type={passwordType}
            value={form.newPassword}
            onChange={handleChange}
            autoComplete="new-password"
            maxLength={policy?.maxLength}
            required
            {...errorProps('newPassword')}
          />
          {rules.length > 0 && (
            <ul className="password-rules" aria-label="Password requirements">
              {rules.map((rule) => {
                const met = rule.test(form.newPassword)
                return (
                  <li key={rule.id} className={met ? 'met' : undefined}>
                    <span className="rule-icon" aria-hidden="true">
                      {met ? '✓' : '•'}
                    </span>
                    {rule.label}
                    <span className="visually-hidden">{met ? ' (met)' : ' (not met)'}</span>
                  </li>
                )
              })}
            </ul>
          )}
          <p className="field-hint">It must also be different from your recent passwords.</p>
          <FieldErrors id="newPassword-errors" errors={fieldErrors.newPassword} />
        </div>

        <div className="field">
          <label htmlFor="confirmPassword">Confirm new password</label>
          <input
            id="confirmPassword"
            name="confirmPassword"
            type={passwordType}
            value={form.confirmPassword}
            onChange={handleChange}
            autoComplete="new-password"
            maxLength={policy?.maxLength}
            required
            {...errorProps('confirmPassword')}
          />
          <FieldErrors id="confirmPassword-errors" errors={fieldErrors.confirmPassword} />
        </div>

        <button type="submit" className="btn-primary" disabled={!schema || submitting}>
          {submitting ? 'Changing password…' : policy ? 'Change password' : 'Loading password policy…'}
        </button>
      </form>
    </section>
  )
}

export default ChangePassword
