import { useEffect, useState } from 'react';
import { apiBase } from '../api/client';
import type { RuntimeEvent } from '../types';

export function useEventStream(token?: string) {
  const [events, setEvents] = useState<RuntimeEvent[]>([]);

  useEffect(() => {
    if (!token) {
      return;
    }

    const url = new URL('/api/v1/events/stream', apiBase);
    url.searchParams.set('token', token);
    const source = new EventSource(url);

    source.onmessage = (message) => {
      try {
        const event = JSON.parse(message.data) as RuntimeEvent;
        setEvents((current) => [event, ...current].slice(0, 40));
      } catch {
        // Ignore malformed events from bootstrap builds.
      }
    };

    source.onerror = () => {
      source.close();
    };

    return () => {
      source.close();
    };
  }, [token]);

  return events;
}
