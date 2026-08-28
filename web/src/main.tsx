import { StrictMode, useEffect } from "react";
import { createRoot } from "react-dom/client";
import { AdminDashboard } from "../app/components/AdminDashboard";
import { LegalBotApp } from "../app/components/LegalBotApp";
import "../app/globals.css";

function App() {
  const isAdmin = window.location.pathname === "/admin" || window.location.pathname.startsWith("/admin/");
  useEffect(() => {
    document.title = isAdmin
      ? "Counsel — Operations"
      : "Counsel — Verified legal research";
  }, [isAdmin]);
  return isAdmin ? <AdminDashboard /> : <LegalBotApp />;
}

const root = document.getElementById("root");
if (!root) throw new Error("Counsel application root is missing.");

createRoot(root).render(
  <StrictMode>
    <App />
  </StrictMode>,
);
