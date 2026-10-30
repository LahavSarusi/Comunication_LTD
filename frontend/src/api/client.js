import axios from 'axios'

// Public, non-secret value (see frontend/.env.example).
const API_URL = import.meta.env.VITE_API_URL ?? 'http://127.0.0.1:4000'

const api = axios.create({
  baseURL: API_URL,
  timeout: 10_000,
  headers: { 'Content-Type': 'application/json' },
  withCredentials: false, // no cookies are needed for registration
})

export async function getPasswordPolicy({ signal } = {}) {
  const { data } = await api.get('/api/auth/password-policy', { signal })
  return data
}

// Sends only the three fields the API expects (confirmPassword stays in the browser).
// The password goes to the server as typed; hashing happens server-side only.
export async function registerUser({ username, email, password }) {
  const { data } = await api.post('/api/auth/register', { username, email, password })
  return data
}

/**
 * Turns an axios error into a message for the user. Server internals are never
 * shown: unexpected statuses get a generic message.
 */
export function parseApiError(error) {
  if (!error.response) {
    return {
      message: 'Cannot reach the server. Please check that the API is running and try again.',
      fieldErrors: {},
    }
  }

  const { status, data } = error.response
  switch (status) {
    case 400:
      return {
        message: data?.formErrors?.[0] ?? 'Please fix the highlighted fields.',
        fieldErrors: data?.fieldErrors ?? {},
      }
    case 409:
      return { message: 'This username or email is already in use.', fieldErrors: {} }
    case 429:
      return { message: 'Too many attempts. Please wait a few minutes and try again.', fieldErrors: {} }
    default:
      return { message: 'Something went wrong on our side. Please try again later.', fieldErrors: {} }
  }
}
