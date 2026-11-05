import { AuthGuard } from "@/components/auth-guard";
import { AccountNav } from "@/components/account-nav";
import { UserDashboard } from "@/components/user-dashboard";
export default function DashboardPage() {
  return (
    <AuthGuard>
      <AccountNav />
      <main id="main" className="container workspace">
        <UserDashboard />
      </main>
    </AuthGuard>
  );
}
