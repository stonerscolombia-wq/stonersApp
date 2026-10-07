import type { CollectionName } from './database';

export interface Actor {
  id: string;
  role: string;
}

type Method = 'PUT' | 'DELETE';
type AnyRecord = Record<string, any>;

const ADMIN_ONLY: CollectionName[] = ['users', 'stores', 'goals', 'sales_budgets'];

/**
 * Devuelve un mensaje de error si `actor` no puede ejecutar `method` sobre el
 * registro, o null si está permitido. `existing` es el registro guardado (si
 * existe) e `incoming` el cuerpo enviado por el cliente.
 */
export function authorizeWrite(
  actor: Actor,
  collection: CollectionName,
  method: Method,
  existing: AnyRecord | null,
  incoming: AnyRecord = {},
): string | null {
  if (actor.role === 'admin') return null;

  const deny = 'No tienes permisos para realizar esta acción.';

  if (ADMIN_ONLY.includes(collection)) return deny;

  // El contador solo visualiza: lo único que puede tocar son sus propias
  // notificaciones (por ejemplo, marcarlas como leídas).
  if (actor.role === 'contador' && collection !== 'notifications') return deny;

  switch (collection) {
    case 'tasks': {
      if (method === 'DELETE') return deny;
      if (existing) {
        const staysMine = incoming.assignedToId === undefined || incoming.assignedToId === actor.id;
        return existing.assignedToId === actor.id && staysMine ? null : deny;
      }
      return incoming.assignedToId === actor.id ? null : deny;
    }
    case 'daily_sales': {
      if (existing && existing.sellerId !== actor.id) return deny;
      if (method === 'PUT' && incoming.sellerId !== actor.id) return deny;
      return null;
    }
    case 'notifications': {
      if (method === 'DELETE') return deny;
      if (existing && existing.userId !== actor.id) return deny;
      return incoming.userId === actor.id ? null : deny;
    }
    case 'activity_logs': {
      if (method === 'DELETE' || existing) return deny;
      return incoming.userId === actor.id ? null : deny;
    }
    case 'sops': {
      // Solo se permite firmar conformidad: agregar la propia firma.
      if (method === 'DELETE' || !existing) return deny;
      const { acknowledgedBy: oldAck = [], ...oldRest } = existing;
      const { acknowledgedBy: newAck = [], ...newRest } = incoming;
      if (JSON.stringify(oldRest) !== JSON.stringify(newRest)) return deny;
      const oldIds = new Set((oldAck as AnyRecord[]).map((a) => a.userId));
      const added = (newAck as AnyRecord[]).filter((a) => !oldIds.has(a.userId));
      const keepsOld = (oldAck as AnyRecord[]).every((a) => (newAck as AnyRecord[]).some((n) => n.userId === a.userId));
      return keepsOld && added.every((a) => a.userId === actor.id) ? null : deny;
    }
    default:
      return deny;
  }
}

/** Acciones de los endpoints dedicados que solo puede hacer un admin. */
export function isAdmin(actor: Actor): boolean {
  return actor.role === 'admin';
}
