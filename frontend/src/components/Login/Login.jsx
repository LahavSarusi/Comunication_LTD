import { useState } from 'react'
import { z } from 'zod'
import { loginUser, parseLoginError } from '../../api/client.js'
import { loginSchema } from '../../validation/loginSchema.js'
// Same card, fields, alerts and buttons as the Register screen.
import '../Register/Register.css'

const EMPTY_FORM = { username: '', password: '' }

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

function Login() {
  const [form, setForm] = useState(EMPTY_FORM)
  const [fieldErrors, setFieldErrors] = useState({})
  const [serverError, setServerError] = useState('')
  const [submitting, setSubmitting] = useState(false)
  const [showPassword, setShowPassword] = useState(false)
  const [loggedInUser, setLoggedInUser] = useState(null)

  function handleChange(event) {
    const { name, value } = event.target
    setForm((previous) => ({ ...previous, [name]: value }))
    setFieldErrors((previous) => ({ ...previous, [name]: undefined }))
    setServerError('')
  }

  async function handleSubmit(event) {
    event.preventDefault()
    if (submitting) return

    const result = loginSchema.safeParse(form)
    if (!result.success) {
      setFieldErrors(z.flattenError(result.error).fieldErrors)
      return
    }

    setSubmitting(true)
    setServerError('')
    try {
      const data = await loginUser(result.data)
      setFieldErrors({})
      setLoggedInUser(data.user)
    } catch (error) {
      const { message, fieldErrors: serverFieldErrors } = parseLoginError(error)
      setServerError(message)
      setFieldErrors(serverFieldErrors)
    } finally {
      // Never keep the password in memory longer than needed, whatever the result.
      setForm((previous) => ({ ...previous, password: '' }))
      setShowPassword(false)
      setSubmitting(false)
    }
  }

  function logout() {
    setLoggedInUser(null)
    setForm(EMPTY_FORM)
  }

  if (loggedInUser) {
    return (
      <section className="register-card" aria-live="polite">
        <h1 className="register-title">Login successful</h1>
        <p className="register-success">
          Welcome back, <strong>{loggedInUser.username}</strong>! You are logged in to the Communication_LTD
          information system.
        </p>
        <button type="button" className="btn-primary" onClick={logout}>
          Log out
        </button>
      </section>
    )
  }

  const errorProps = (name) => ({
    'aria-invalid': fieldErrors[name]?.length ? true : undefined,
    'aria-describedby': fieldErrors[name]?.length ? `login-${name}-errors` : undefined,
  })

  return (
    <section className="register-card">
      <h1 className="register-title">Log in</h1>
      <p className="register-subtitle">Log in to the Communication_LTD information system.</p>

      {serverError && (
        <div className="alert alert-error" role="alert">
          {serverError}
        </div>
      )}

      <form className="register-form" onSubmit={handleSubmit} noValidate>
        <div className="field">
          <label htmlFor="login-username">Username</label>
          <input
            id="login-username"
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
          <FieldErrors id="login-username-errors" errors={fieldErrors.username} />
        </div>

        <div className="field">
          <div className="field-label-row">
            <label htmlFor="login-password">Password</label>
            <button
              type="button"
              className="btn-link"
              onClick={() => setShowPassword((visible) => !visible)}
              aria-pressed={showPassword}
              aria-controls="login-password"
            >
              {showPassword ? 'Hide' : 'Show'}
            </button>
          </div>
          <input
            id="login-password"
            name="password"
            type={showPassword ? 'text' : 'password'}
            value={form.password}
            onChange={handleChange}
            autoComplete="current-password"
            required
            {...errorProps('password')}
          />
          <FieldErrors id="login-password-errors" errors={fieldErrors.password} />
        </div>

        <button type="submit" className="btn-primary" disabled={submitting}>
          {submitting ? 'Logging in…' : 'Log in'}
        </button>
      </form>
    </section>
  )
}

export default Login
