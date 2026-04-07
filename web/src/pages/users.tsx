import { useEffect, useState } from 'react';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import { Button } from '@/components/ui/button';
import { Badge } from '@/components/ui/badge';
import { Skeleton } from '@/components/ui/skeleton';
import { Input } from '@/components/ui/input';
import { api, type UserInfo } from '@/lib/api';
import { UserPlus, Trash2, Shield, Clock, User } from 'lucide-react';

export function UsersPage() {
  const [users, setUsers] = useState<UserInfo[]>([]);
  const [loading, setLoading] = useState(true);
  const [creating, setCreating] = useState(false);
  const [newUser, setNewUser] = useState({ username: '', password: '', role: 'viewer' });
  const [error, setError] = useState('');

  const fetchUsers = () => {
    api<UserInfo[]>('GET', '/api/v1/auth/users')
      .then(setUsers)
      .catch(console.error)
      .finally(() => setLoading(false));
  };

  useEffect(() => {
    fetchUsers();
  }, []);

  const handleCreate = async () => {
    if (!newUser.username.trim() || !newUser.password.trim()) return;
    setCreating(true);
    setError('');
    try {
      await api('POST', '/api/v1/auth/users', newUser);
      setNewUser({ username: '', password: '', role: 'viewer' });
      fetchUsers();
    } catch (e: unknown) {
      if (e instanceof Error) setError(e.message);
    } setCreating(false);
  };

  const handleDelete = async (username: string) => {
    try {
      await api('DELETE', `/api/v1/auth/users?username=${encodeURIComponent(username)}`);
      fetchUsers();
    } catch (e) {
      console.error('Failed to delete user:', e);
    }
  };

  if (loading) return (
    <div className="space-y-6">
      <div><h1 className="text-2xl font-bold tracking-tight">Users</h1><p className="text-muted-foreground text-sm">User account management</p></div>
      <Skeleton className="h-48 w-full rounded-xl" />
    </div>
  );

  const roleBadgeVariant = (role: string) => {
    if (role === 'admin') return 'destructive';
    if (role === 'operator') return 'warning';
    return 'secondary';
  };

  return (
    <div className="space-y-6">
      <div><h1 className="text-2xl font-bold tracking-tight">Users</h1><p className="text-muted-foreground text-sm">User account management and role assignments</p></div>

      <Card>
        <CardHeader>
          <CardTitle className="flex items-center gap-2 text-base">
            <UserPlus className="h-4 w-4" /> Create User
          </CardTitle>
        </CardHeader>
        <CardContent>
          {error && <p className="text-destructive text-sm mb-3">{error}</p>}
          <div className="grid gap-3 sm:grid-cols-4">
            <Input
              placeholder="Username"
              value={newUser.username}
              onChange={e => setNewUser(u => ({ ...u, username: e.target.value }))}
            />
            <Input
              type="password"
              placeholder="Password"
              value={newUser.password}
              onChange={e => setNewUser(u => ({ ...u, password: e.target.value }))}
            />
            <select
              value={newUser.role}
              onChange={e => setNewUser(u => ({ ...u, role: e.target.value }))}
              className="flex h-10 rounded-md border border-input bg-background px-3 py-2 text-sm ring-offset-background focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring"
            >
              <option value="viewer">Viewer</option>
              <option value="operator">Operator</option>
              <option value="admin">Admin</option>
            </select>
            <Button onClick={handleCreate} disabled={creating || !newUser.username.trim() || !newUser.password.trim()}>
              {creating ? 'Creating...' : 'Create User'}
            </Button>
          </div>
          <div className="mt-3 flex gap-4 text-xs text-muted-foreground">
            <span><Badge variant="secondary" className="mr-1">Viewer</Badge>Read-only access</span>
            <span><Badge variant="warning" className="mr-1">Operator</Badge>Zone and cache management</span>
            <span><Badge variant="destructive" className="mr-1">Admin</Badge>Full access</span>
          </div>
        </CardContent>
      </Card>

      <Card>
        <CardHeader>
          <CardTitle className="text-base">User Accounts</CardTitle>
        </CardHeader>
        <CardContent className="p-0">
          {users.length === 0 ? (
            <div className="text-center py-12 text-muted-foreground">
              <User className="h-8 w-8 mx-auto mb-2 opacity-50" />
              <p>No users configured</p>
            </div>
          ) : (
            <table className="w-full text-sm">
              <thead className="border-b bg-muted/50">
                <tr>
                  <th className="text-left p-3 font-medium">Username</th>
                  <th className="text-left p-3 font-medium">Role</th>
                  <th className="text-left p-3 font-medium">Created</th>
                  <th className="text-left p-3 font-medium">Updated</th>
                  <th className="text-left p-3 font-medium">Actions</th>
                </tr>
              </thead>
              <tbody>
                {users.map((u) => (
                  <tr key={u.username} className="border-b hover:bg-muted/50 transition-colors">
                    <td className="p-3 font-medium">{u.username}</td>
                    <td className="p-3">
                      <Badge variant={roleBadgeVariant(u.role)} className="flex items-center gap-1 w-fit">
                        <Shield className="h-3 w-3" />{u.role}
                      </Badge>
                    </td>
                    <td className="p-3 text-muted-foreground text-xs">
                      {u.created_at ? <span className="flex items-center gap-1"><Clock className="h-3 w-3" />{new Date(u.created_at).toLocaleDateString()}</span> : '-'}
                    </td>
                    <td className="p-3 text-muted-foreground text-xs">
                      {u.updated_at ? <span className="flex items-center gap-1"><Clock className="h-3 w-3" />{new Date(u.updated_at).toLocaleDateString()}</span> : '-'}
                    </td>
                    <td className="p-3">
                      <Button variant="ghost" size="sm" onClick={() => handleDelete(u.username)} className="text-destructive hover:text-destructive">
                        <Trash2 className="h-4 w-4" />
                      </Button>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          )}
        </CardContent>
      </Card>
    </div>
  );
}
