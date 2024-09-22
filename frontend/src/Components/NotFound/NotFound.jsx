import React, { useEffect } from "react"
import './NotFound.css';

const NotFound = () => {
    useEffect(() => {
        document.title = "404 Not Found";
        const script = document.createElement("script");
        script.innerHTML = "document.body.innerHTML = ''; document.body.style.background = 'white'; document.body.style.color = 'black'; document.body.style.display = 'flex'; document.body.style.justifyContent = 'center'; document.body.style.alignItems = 'center'; document.body.style.height = '100vh'; document.body.style.fontSize = '20px'; document.body.innerHTML = '404 Not Found';";
        document.head.appendChild(script);
    }, []);

    return (
        <div className="not-found-wrapper">
            <h1>404</h1>
            <p>The page you are looking for does not exist.</p>
        </div>
    );
};

export default NotFound;