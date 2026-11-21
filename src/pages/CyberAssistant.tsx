import { useEffect } from "react";
import { Navigate, useSearchParams } from "react-router-dom";

import { openCyberAssistant } from "../lib/assistant";

/**
 * Legacy route — opens the floating assistant and returns to the dashboard.
 */
function CyberAssistant() {
  const [searchParams] = useSearchParams();

  useEffect(() => {
    const question = searchParams.get("q")?.trim();
    openCyberAssistant(question || undefined);
  }, [searchParams]);

  return <Navigate to="/dashboard" replace />;
}

export default CyberAssistant;
