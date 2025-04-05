import { NextResponse } from 'next/server';
import { cookies } from 'next/headers';
import { registerUser } from '@/lib/auth';

export const dynamic = 'force-dynamic';

export async function POST(request) {
  try {
    const userData = await request.json();
    
    // Validate required fields
    if (!userData.email || !userData.password) {
      return NextResponse.json(
        { error: 'Email and password are required' },
        { status: 400 }
      );
    }
    
    // Register user with hashed password
    const result = await registerUser(userData);
    
    if (!result.success) {
      return NextResponse.json(
        { error: result.error },
        { status: 400 }
      );
    }
    
    // Set token in cookie
    const cookieStore = await cookies();
    cookieStore.set('token', result.token, {
      httpOnly: true,
      secure: process.env.NODE_ENV === 'production',
      maxAge: 7 * 24 * 60 * 60, // 7 days
      path: '/',
      sameSite: 'lax'
    });
    
    // Indicate that the user needs to set up their organization
    return NextResponse.json({
      success: true,
      message: 'Registration successful',
      user: result.user,
      token: result.token,
      setupRequired: true,
      nextStep: 'create-organization'
    });
    
  } catch (error) {
    console.error('Registration error:', error);
    return NextResponse.json(
      { error: 'An error occurred during registration' },
      { status: 500 }
    );
  }
}