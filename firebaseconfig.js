import { initializeApp } from "https://www.gstatic.com/firebasejs/10.14.1/firebase-app.js";
import {
  getAuth,
  GoogleAuthProvider,
  signInWithRedirect,
  getRedirectResult,
} from "https://www.gstatic.com/firebasejs/10.14.1/firebase-auth.js";

const firebaseConfig = {
  apiKey: "AIzaSyCmHaayfQy0WSOE1HG_bDjs4tiVJFDFb84",
  authDomain: "vybera.firebaseapp.com",
  projectId: "vybera",
  storageBucket: "vybera.firebasestorage.app",
  messagingSenderId: "544899681732",
  appId: "1:544899681732:web:72950958f1ac6b83356891",
};

const app = initializeApp(firebaseConfig);
const auth = getAuth(app);
const googleProvider = new GoogleAuthProvider();
googleProvider.setCustomParameters({
  prompt: "select_account",
});

function normalizeLocalAuthOrigin() {
  const isFilePreview = window.location.protocol === "file:";
  const isLoopbackIp = ["127.0.0.1", "0.0.0.0"].includes(window.location.hostname);
  if (!isFilePreview && !isLoopbackIp) return false;

  const port = window.VYBERA_DEV_PORT || "3003";
  const path = isFilePreview
    ? "/"
    : window.location.pathname;
  window.location.href = `http://localhost:${port}${path}${window.location.search}${window.location.hash}`;
  return true;
}

window.vyberaFirebaseGoogleReady = true;
async function finishGoogleUser(user) {
  const displayName = user.displayName || "Google User";
  const email = user.email || "";
  for (let i = 0; i < 40 && typeof window.applySocialLogin !== "function"; i += 1) {
    await new Promise((resolve) => setTimeout(resolve, 100));
  }
  if (typeof window.applySocialLogin !== "function") {
    throw new Error("App login is still loading. Please try again.");
  }
  await window.applySocialLogin({
    name: displayName,
    email,
    photoURL: user.photoURL || "",
  });
}

getRedirectResult(auth)
  .then((result) => {
    if (result && result.user) return finishGoogleUser(result.user);
  })
  .catch((err) => {
    console.error("Google redirect result failed:", err);
  });

window.vyberaFirebaseGoogleSignIn = async function vyberaFirebaseGoogleSignIn() {
  try {
    if (normalizeLocalAuthOrigin()) return;
    return signInWithRedirect(auth, googleProvider);
  } catch (err) {
    console.error("Google sign-in failed:", err);

    if (err.code === "auth/popup-closed-by-user" || err.code === "auth/cancelled-popup-request") {
      return;
    }

    if (err.code === "auth/unauthorized-domain") {
      alert(
        `Google login is blocked for "${window.location.hostname}". ` +
        "Add this exact hostname in Firebase Console > Authentication > Settings > Authorized domains. " +
        "For your current ngrok URL, add: skydiver-tapering-pouch.ngrok-free.dev"
      );
      return;
    }

    alert(err.message || "Google sign-in failed. Please try again.");
  }
};

window.signInWithGoogle = window.vyberaFirebaseGoogleSignIn;
