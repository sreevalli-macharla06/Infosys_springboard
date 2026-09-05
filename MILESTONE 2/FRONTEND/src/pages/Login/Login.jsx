import { useState } from "react";
import { useNavigate } from "react-router-dom";

import {
  FaShieldAlt,
  FaUser,
  FaLock,
  FaEye,
  FaEyeSlash,
  FaCheckCircle,
} from "react-icons/fa";

function Login() {
  const navigate = useNavigate();

  const [showPassword, setShowPassword] = useState(false);
  // Controlled inputs for client-side validation
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [formError, setFormError] = useState("");

  // NOTE: No real authentication is implemented here.
  // Authentication (JWT / session tokens / backend verification) is explicitly
  // out of scope for Milestone 1. This form validates that fields are not
  // empty before granting access to the dashboard.
  const handleLogin = (e) => {
    e.preventDefault();
    setFormError("");

    if (!email.trim()) {
      setFormError("Email address is required.");
      return;
    }
    if (!password.trim()) {
      setFormError("Password is required.");
      return;
    }

    navigate("/dashboard");
  };

  return (
    <div className="relative min-h-screen overflow-hidden bg-slate-950">

      {/* ================= Background Glow ================= */}

      <div className="absolute inset-0">

        <div className="absolute -top-40 -left-40 h-[550px] w-[550px] rounded-full bg-blue-600/20 blur-[170px]" />

        <div className="absolute -bottom-40 -right-40 h-[550px] w-[550px] rounded-full bg-cyan-500/20 blur-[170px]" />

      </div>

      {/* ================= Main Container ================= */}

      <div className="relative z-10 flex min-h-screen items-center justify-center px-8 py-10">

        <div className="flex w-full max-w-7xl items-center justify-between gap-20">

          {/* ========================================================= */}
          {/* LEFT INFORMATION PANEL                                  */}
          {/* ========================================================= */}

          <div className="hidden lg:flex flex-1 flex-col">

            {/* Logo + Heading */}

            <div className="flex items-center gap-5">

              <div className="rounded-3xl bg-blue-600 p-6 shadow-2xl">

                <FaShieldAlt className="text-5xl text-white" />

              </div>

              <div>

                <h1 className="text-5xl font-extrabold text-white">

                  SentinelAI Security

                </h1>

                <p className="mt-3 text-xl text-slate-300">

                  AI-Assisted Threat Detection Dashboard

                </p>

              </div>

            </div>

            {/* Description */}

            <p className="mt-10 max-w-xl text-lg leading-9 text-slate-400">

              Monitor security logs in real time, detect suspicious
              activities using AI, calculate dynamic risk scores, and
              visualize critical insights through an enterprise
              Security Operations Center dashboard.

            </p>

            {/* Feature Badge */}

            <div className="mt-10 inline-flex w-fit rounded-full border border-blue-500/30 bg-blue-500/10 px-5 py-2">

              <span className="text-sm font-medium text-blue-300">

                AI-Powered Security Analytics

              </span>

            </div>

            {/* Features */}

            <div className="mt-12 space-y-7">

              <div className="flex items-center gap-4">

                <FaCheckCircle className="text-2xl text-blue-500" />

                <span className="text-lg text-slate-200">

                  Real-time Log Monitoring

                </span>

              </div>

              <div className="flex items-center gap-4">

                <FaCheckCircle className="text-2xl text-blue-500" />

                <span className="text-lg text-slate-200">

                  AI-Assisted Threat Detection

                </span>

              </div>

              <div className="flex items-center gap-4">

                <FaCheckCircle className="text-2xl text-blue-500" />

                <span className="text-lg text-slate-200">

                  Dynamic Risk Scoring

                </span>

              </div>

              <div className="flex items-center gap-4">

                <FaCheckCircle className="text-2xl text-blue-500" />

                <span className="text-lg text-slate-200">

                  Interactive SOC Dashboard

                </span>

              </div>

            </div>

          </div>

          {/* ========================================================= */}
          {/* LOGIN CARD                                               */}
          {/* ========================================================= */}

          <div className="w-full max-w-lg rounded-3xl border border-slate-700 bg-slate-900/80 p-10 shadow-2xl backdrop-blur-md">

            {/* Logo */}

            <div className="flex justify-center">

              <div className="rounded-full bg-blue-600 p-5 shadow-xl">

                <FaShieldAlt className="text-5xl text-white" />

              </div>

            </div>

            {/* Heading */}

            <div className="mt-6 text-center">

              <h2 className="text-4xl font-bold text-white">

                SentinelAI Security

              </h2>

              <p className="mt-3 text-slate-400">

                AI-Assisted Threat Detection Dashboard

              </p>

              <p className="mt-2 text-sm font-medium text-blue-400">

                Secure SOC Analyst Login

              </p>

              <p className="mt-2 text-xs text-slate-500">

                Secure authentication for authorized analysts only.

              </p>

            </div>

            {/* Login Form */}

            <form
              onSubmit={handleLogin}
              className="mt-10 space-y-6"
            >
            
                          {/* ================= EMAIL ================= */}

              <div>

                <label className="mb-2 block text-sm text-slate-300">
                  Email Address
                </label>

                <div className="relative">

                  <FaUser className="absolute left-4 top-1/2 -translate-y-1/2 text-slate-500" />

                  <input
                    id="login-email"
                    type="email"
                    value={email}
                    onChange={(e) => { setEmail(e.target.value); setFormError(""); }}
                    placeholder="soc.analyst@company.com"
                    className="h-14 w-full rounded-xl border border-slate-700 bg-slate-950 pl-12 pr-4 text-white placeholder:text-slate-500 outline-none transition-all duration-200 focus:border-blue-500 focus:ring-2 focus:ring-blue-500/20"
                  />

                </div>

              </div>

              {/* ================= PASSWORD ================= */}

              <div>

                <label className="mb-2 block text-sm text-slate-300">
                  Password
                </label>

                <div className="relative">

                  <FaLock className="absolute left-4 top-1/2 -translate-y-1/2 text-slate-500" />

                  <input
                    id="login-password"
                    type={showPassword ? "text" : "password"}
                    value={password}
                    onChange={(e) => { setPassword(e.target.value); setFormError(""); }}
                    placeholder="Enter your password"
                    className="h-14 w-full rounded-xl border border-slate-700 bg-slate-950 pl-12 pr-12 text-white placeholder:text-slate-500 outline-none transition-all duration-200 focus:border-blue-500 focus:ring-2 focus:ring-blue-500/20"
                  />

                  <button
                    type="button"
                    onClick={() => setShowPassword(!showPassword)}
                    className="absolute right-4 top-1/2 -translate-y-1/2 text-slate-500 transition hover:text-white"
                  >

                    {showPassword ? <FaEyeSlash /> : <FaEye />}

                  </button>

                </div>

              </div>

              {/* ================= VALIDATION ERROR ================= */}
              {formError && (
                <p id="login-error" className="text-sm font-medium text-red-400" role="alert">
                  {formError}
                </p>
              )}

              {/* ================= REMEMBER ================= */}

              <div className="flex items-center justify-between text-sm">

                <label className="flex items-center gap-3 text-slate-300">

                  <input
                    type="checkbox"
                    className="h-4 w-4 cursor-pointer rounded accent-blue-600"
                  />

                  Remember Me

                </label>

                <button
                  type="button"
                  className="font-medium text-blue-400 transition hover:text-blue-300"
                >
                  Forgot Password?
                </button>

              </div>

              {/* ================= LOGIN BUTTON ================= */}

              <button
                type="submit"
                className="w-full rounded-xl bg-blue-600 py-3.5 text-lg font-semibold text-white shadow-lg shadow-blue-600/20 transition-all duration-200 hover:scale-[1.02] hover:bg-blue-700 active:scale-100"
              >
                Access Dashboard →
              </button>

            </form>

            {/* ================= FOOTER ================= */}

            <div className="mt-10 border-t border-slate-700 pt-6 text-center">

              <p className="text-sm font-medium text-slate-400">
                Enterprise AI Security Platform
              </p>

              <p className="mt-2 text-xs text-slate-500">
                Powered by AI-Assisted Threat Detection
              </p>

              <p className="mt-3 text-xs text-slate-600">
                © 2026 SentinelAI. All Rights Reserved.
              </p>

            </div>

          </div>

        </div>

      </div>

    </div>

  );
}

export default Login;