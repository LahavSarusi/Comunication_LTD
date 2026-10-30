import Register from './components/Register/Register.jsx'
import './App.css'

function App() {
  return (
    <div className="app">
      <header className="app-header">
        <span className="brand">Communication_LTD</span>
        <span className="tagline">Internet packages for every business sector</span>
      </header>

      <main className="app-main">
        <Register />
      </main>

      <footer className="app-footer">Communication_LTD · Secure registration</footer>
    </div>
  )
}

export default App
