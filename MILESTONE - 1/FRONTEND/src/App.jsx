import { BrowserRouter, Routes, Route } from "react-router-dom";

import Login from "./pages/Login/Login";
import DashboardLayout from "./layouts/DashboardLayout";
import Overview from "./pages/Dashboard/Overview";
import SecurityEvents from "./pages/Dashboard/SecurityEvents";
import ThreatIntel from "./pages/Dashboard/ThreatIntel";
import Vulnerabilities from "./pages/Dashboard/Vulnerabilities";
import Analytics from "./pages/Dashboard/Analytics";

function App() {
  return (
    <BrowserRouter>
      <Routes>
        <Route path="/" element={<Login />} />
        <Route path="/dashboard" element={<DashboardLayout />}>
          <Route index element={<Overview />} />
          <Route path="events" element={<SecurityEvents />} />
          <Route path="threat-intel" element={<ThreatIntel />} />
          <Route path="vulnerabilities" element={<Vulnerabilities />} />
          <Route path="analytics" element={<Analytics />} />
        </Route>
      </Routes>
    </BrowserRouter>
  );
}

export default App;
