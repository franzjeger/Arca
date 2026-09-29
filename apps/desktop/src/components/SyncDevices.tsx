import { useEffect, useState } from "react";
import { api, type SyncDevice } from "../lib/api";

/**
 * The devices that push this vault, and when each last did. Drive can hold
 * back a device's changes without anything failing; this is where that shows,
 * as a phone that "last synced" days ago when it was used this morning.
 */
export function SyncDevices({ refreshKey }: { refreshKey?: unknown }) {
  const [devices, setDevices] = useState<SyncDevice[] | null>(null);
  useEffect(() => {
    let alive = true;
    api.syncDevices()
      .then((list) => { if (alive) setDevices(list); })
      .catch(() => { if (alive) setDevices([]); });
    return () => { alive = false; };
  }, [refreshKey]);

  if (!devices?.length) return null;
  return (
    <ul aria-label="Devices syncing this vault" className="mt-1 space-y-0.5 text-[12px] text-neutral-400">
      {devices.map((device, i) => (
        <li key={`${device.name}-${i}`} className="flex justify-between gap-3">
          <span className="truncate text-neutral-200">
            {device.name}
            {device.thisDevice && <span className="text-neutral-500"> (this computer)</span>}
          </span>
          <span className="shrink-0">synced {new Date(device.lastUpload).toLocaleString()}</span>
        </li>
      ))}
    </ul>
  );
}
