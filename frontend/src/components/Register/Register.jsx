import { useEffect, useMemo, useState } from 'react'
import { z } from 'zod'
import { getPasswordPolicy, parseApiError, registerUser } from '../../api/client.js'
import { buildRegisterSchema, getPasswordRules } from '../../validation/registerSchema.js'
import './Register.css'

const EMPTY_FORM = { username: '', email: '', password: '', confirmPassword: '' }

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

function Register() {
  const [policy, setPolicy] = useState(null)
  const [policyError, setPolicyError] = useState('')
  const [policyRequest, setPolicyRequest] = useState(0)
  const [form, setForm] = useState(EMPTY_FORM)
  const [fieldErrors, setFieldErrors] = useState({})
  const [serverError, setServerError] = useState('')
  const [submitting, setSubmitting] = useState(false)
  const [showPassword, setShowPassword] = useState(false)
  const [registeredUser, setRegisteredUser] = useState(null)

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
  const schema = useMemo(() => (policy ? buildRegisterSchema(policy) : null), [policy])

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
      const { username, email, password } = result.data
      const data = await registerUser({ username, email, password })
      // Never keep the password in memory longer than needed.
      setForm(EMPTY_FORM)
      setFieldErrors({})
      setShowPassword(false)
      setRegisteredUser(data.user)
    } catch (error) {
      const { message, fieldErrors: serverFieldErrors } = parseApiError(error)
      setServerError(message)
      setFieldErrors(serverFieldErrors)
    } finally {
      setSubmitting(false)
    }
  }

  if (registeredUser) {
    return (
      <section className="register-card" aria-live="polite">
        <h1 className="register-title">Account created</h1>
        <p className="register-success">
          Welcome, <strong>{registeredUser.username}</strong>! Your account ({registeredUser.email}) is ready.
        </p>
        <button type="button" className="btn-primary" onClick={() => setRegisteredUser(null)}>
          Register another user
        </button>
      </section>
    )
  }

  const errorProps = (name) => ({
    'aria-invalid': fieldErrors[name]?.length ? true : undefined,
    'aria-describedby': fieldErrors[name]?.length ? `${name}-errors` : undefined,
  })

  return (
    <section className="register-card">
      <h1 className="register-title">Create your account</h1>
      <p className="register-subtitle">Register to manage your Communication_LTD internet packages.</p>

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
          <p className="field-hint">3-30 characters: letters, digits or underscore (saved in lowercase).</p>
          <FieldErrors id="username-errors" errors={fieldErrors.username} />
        </div>

        <div className="field">
          <label htmlFor="email">Email</label>
          <input
            id="email"
            name="email"
            type="email"
            value={form.email}
            onChange={handleChange}
            autoComplete="email"
            spellCheck={false}
            maxLength={254}
            required
            {...errorProps('email')}
          />
          <FieldErrors id="email-errors" errors={fieldErrors.email} />
        </div>

        <div className="field">
          <div className="field-label-row">
            <label htmlFor="password">Password</label>
            <button
              type="button"
              className="btn-link"
              onClick={() => setShowPassword((visible) => !visible)}
              aria-pressed={showPassword}
              aria-controls="password confirmPassword"
            >
              {showPassword ? 'Hide' : 'Show'}
            </button>
          </div>
          <input
            id="password"
            name="password"
            type={showPassword ? 'text' : 'password'}
            value={form.password}
            onChange={handleChange}
            autoComplete="new-password"
            maxLength={policy?.maxLength}
            required
            {...errorProps('password')}
          />
          {rules.length > 0 && (
            <ul className="password-rules" aria-label="Password requirements">
              {rules.map((rule) => {
                const met = rule.test(form.password)
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
          <FieldErrors id="password-errors" errors={fieldErrors.password} />
        </div>

        <div className="field">
          <label htmlFor="confirmPassword">Confirm password</label>
          <input
            id="confirmPassword"
            name="confirmPassword"
            type={showPassword ? 'text' : 'password'}
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
          {submitting ? 'Creating account…' : policy ? 'Create account' : 'Loading password policy…'}
        </button>
      </form>
    </section>
  )
}

export default Register
