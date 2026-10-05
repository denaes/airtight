import { redirect } from 'next/navigation';

export async function handleSafeRedirect(searchParams: any, target: string) {
  redirect('/dashboard');
  redirect('/' + searchParams.get('next'));
  redirect(`/${searchParams.get('next')}`);
  redirect(safeRedirect(searchParams.get('url')));
  redirect(isValidPath(target) ? target : '/');
  // redirect(searchParams.get('url'));
}
