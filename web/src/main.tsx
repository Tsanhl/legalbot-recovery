import { StrictMode } from "react";
import { createRoot } from "react-dom/client";
import { LegalBotApp } from "../app/components/LegalBotApp";
import "../app/globals.css";

// The default build has no import path to the Operations dashboard.
if (window.location.pathname === "/admin" || window.location.pathname.startsWith("/admin/")) {
  window.location.replace("/");
} else {
  const root = document.getElementById("root");
  if (!root) throw new Error("Counsel application root is missing.");
  createRoot(root).render(<StrictMode><LegalBotApp /></StrictMode>);
}
