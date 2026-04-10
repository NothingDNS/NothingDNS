import { createContext, useContext, useState, useCallback, useEffect, type ReactNode } from 'react';
import { X, CheckCircle, AlertCircle, Info, AlertTriangle } from 'lucide-react';

type NotificationType = 'success' | 'error' | 'info' | 'warning';

interface Notification {
  id: string;
  type: NotificationType;
  title: string;
  message?: string;
  timestamp: Date;
}

interface NotificationContextValue {
  notifications: Notification[];
  addNotification: (type: NotificationType, title: string, message?: string) => void;
  removeNotification: (id: string) => void;
  clearNotifications: () => void;
}

const NotificationContext = createContext<NotificationContextValue | null>(null);

export function NotificationProvider({ children }: { children: ReactNode }) {
  const [notifications, setNotifications] = useState<Notification[]>([]);

  const addNotification = useCallback((type: NotificationType, title: string, message?: string) => {
    const id = `notif-${Date.now()}-${Math.random().toString(36).slice(2)}`;
    setNotifications(prev => [...prev, { id, type, title, message, timestamp: new Date() }]);

    // Auto-remove after 5s
    setTimeout(() => {
      setNotifications(prev => prev.filter(n => n.id !== id));
    }, 5000);
  }, []);

  const removeNotification = useCallback((id: string) => {
    setNotifications(prev => prev.filter(n => n.id !== id));
  }, []);

  const clearNotifications = useCallback(() => {
    setNotifications([]);
  }, []);

  // Set global notification function so non-React code can trigger notifications
  useEffect(() => {
    setGlobalNotificationFn(addNotification);
  }, [addNotification]);

  return (
    <NotificationContext.Provider value={{ notifications, addNotification, removeNotification, clearNotifications }}>
      {children}
      <NotificationToast notifications={notifications} onRemove={removeNotification} />
    </NotificationContext.Provider>
  );
}

export function useNotification() {
  const ctx = useContext(NotificationContext);
  if (!ctx) throw new Error('useNotification must be used within NotificationProvider');
  return ctx;
}

function NotificationToast({ notifications, onRemove }: { notifications: Notification[]; onRemove: (id: string) => void }) {
  if (notifications.length === 0) return null;

  const iconFor = (type: NotificationType) => {
    switch (type) {
      case 'success': return <CheckCircle className="h-4 w-4 text-success" />;
      case 'error': return <AlertCircle className="h-4 w-4 text-destructive" />;
      case 'warning': return <AlertTriangle className="h-4 w-4 text-warning" />;
      case 'info': return <Info className="h-4 w-4 text-primary" />;
    }
  };

  const borderFor = (type: NotificationType) => {
    switch (type) {
      case 'success': return 'border-l-success';
      case 'error': return 'border-l-destructive';
      case 'warning': return 'border-l-warning';
      case 'info': return 'border-l-primary';
    }
  };

  return (
    <div className="fixed bottom-4 right-4 z-[100] space-y-2 max-w-sm">
      {notifications.map(n => (
        <div
          key={n.id}
          className={`flex items-start gap-3 bg-background border border-l-4 rounded-lg shadow-lg p-4 animate-in slide-in-from-right ${borderFor(n.type)}`}
        >
          {iconFor(n.type)}
          <div className="flex-1 min-w-0">
            <p className="font-medium text-sm">{n.title}</p>
            {n.message && <p className="text-xs text-muted-foreground mt-1">{n.message}</p>}
          </div>
          <button
            onClick={() => onRemove(n.id)}
            className="text-muted-foreground hover:text-foreground shrink-0"
          >
            <X className="h-4 w-4" />
          </button>
        </div>
      ))}
    </div>
  );
}

// Global notification function for use outside React
let globalAddNotif: ((type: NotificationType, title: string, message?: string) => void) | null = null;

export function setGlobalNotificationFn(fn: (type: NotificationType, title: string, message?: string) => void) {
  globalAddNotif = fn;
}

export function notify(type: NotificationType, title: string, message?: string) {
  if (globalAddNotif) {
    globalAddNotif(type, title, message);
  }
}