import { useState } from 'react'
import ChangePassword from './components/ChangePassword/ChangePassword.jsx'
import Login from './components/Login/Login.jsx'
import Register from './components/Register/Register.jsx'
import './App.css'

const SCREENS = [
  { id: 'register', label: 'Register', Component: Register },
  { id: 'login', label: 'Login', Component: Login },
  { id: 'change-password', label: 'Change password', Component: ChangePassword },
]

function App() {
  const [screenId, setScreenId] = useState(SCREENS[0].id)
  const { Component } = SCREENS.find((screen) => screen.id === screenId)

  return (
    <div className="app">
      <header className="app-header">
        <span className="brand">Communication_LTD</span>
        <span className="tagline">Internet packages for every business sector</span>
      </header>

      <main className="app-main">
        <div className="app-content">
          <nav className="screen-tabs" aria-label="Screens">
            {SCREENS.map((screen) => (
              <button
                key={screen.id}
                type="button"
                className="screen-tab"
                aria-current={screen.id === screenId ? 'page' : undefined}
                onClick={() => setScreenId(screen.id)}
              >
                {screen.label}
              </button>
            ))}
          </nav>

          {/* Only the active screen is mounted, so switching screens discards
              everything typed in the other one, passwords included. */}
          <Component key={screenId} />
        </div>
      </main>

      <footer className="app-footer">Communication_LTD · Secure account management</footer>
    </div>
  )
}

export default App
