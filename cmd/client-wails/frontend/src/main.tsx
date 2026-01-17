import './index.css' // Load Tailwind FIRST
// import './style.css' // Removed to avoid conflict
import React from 'react'
import {createRoot} from 'react-dom/client'
import App from './App'

const container = document.getElementById('root')

const root = createRoot(container!)

root.render(
    <React.StrictMode>
        <App/>
    </React.StrictMode>
)
