import { useEffect } from 'react';

const BackgroundMonitor = ({ onSecurityUpdate, addLog }) => {
  useEffect(() => {
    const bc = new BroadcastChannel('cognisafe_link');
    
    // Listen for Remote Simulator Commands
    bc.onmessage = (event) => {
      addLog(`📡 REMOTE_SIGNAL: ${event.data.type}`);
      onSecurityUpdate(event.data.payload.risk);
    };

    const handleInteractions = (e) => {
      // Level 2: Detect rapid clicking (Bot behavior)
      if (e.detail > 5) {
        onSecurityUpdate(90);
        addLog("⚠️ MACRO_CLICK_DETECTED");
      }
    };

    window.addEventListener('click', handleInteractions);
    return () => {
      window.removeEventListener('click', handleInteractions);
      bc.close();
    };
  }, [onSecurityUpdate, addLog]);

  return null;
};
export default BackgroundMonitor;