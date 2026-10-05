import { redirect } from 'next/navigation';
import { NextRequest } from 'next/server';

export async function handleRedirect(searchParams: any, req: NextRequest) {
  redirect(searchParams.get('returnTo'));
  redirect(searchParams.returnUrl);
  redirect(req.nextUrl.searchParams.get('next'));
  redirect(await searchParams.callback);
  redirect(searchParams.get('url') as string);
  redirect(searchParams.get('url') ?? '/dashboard');
}
