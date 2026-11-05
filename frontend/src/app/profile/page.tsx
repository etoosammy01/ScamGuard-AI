import { AuthGuard } from "@/components/auth-guard";
import { AccountNav } from "@/components/account-nav";
import { ProfileForm } from "@/components/profile-form";
export default function ProfilePage() {
  return (
    <AuthGuard>
      <AccountNav />
      <main id="main" className="container workspace">
        <ProfileForm />
      </main>
    </AuthGuard>
  );
}
