import { useEffect, useState } from "react";

function formatUtc(date: Date) {
  return date
    .toISOString()
    .replace("T", " ")
    .replace(/\.\d{3}Z$/, " UTC");
}

export function LiveUtcClock() {
  const [now, setNow] = useState<Date | null>(null);

  useEffect(() => {
    setNow(new Date());
    const id = window.setInterval(() => setNow(new Date()), 1000);
    return () => window.clearInterval(id);
  }, []);

  return (
    <span className="font-mono text-[10px] uppercase tracking-widest text-muted-foreground">
      {now ? formatUtc(now) : "syncing UTC"}
    </span>
  );
}
