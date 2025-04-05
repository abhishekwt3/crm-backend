import { NextResponse } from 'next/server';
import prisma from '@/lib/prisma'; // Use a singleton instance
import { verifyToken } from '@/lib/auth';
import { cookies } from 'next/headers';

export const dynamic = 'force-dynamic'; // Ensure route is not cached

export async function GET(request) {
  try {
    // Get token from cookies and/or authorization header
    const cookieStore = await cookies();
    const tokenFromCookie = cookieStore.get('token')?.value;
    
    const authHeader = request.headers.get('authorization');
    const tokenFromHeader = authHeader && authHeader.startsWith('Bearer ') 
      ? authHeader.substring(7) 
      : null;
    
    const token = tokenFromCookie || tokenFromHeader;
    
    // No token found
    if (!token) {
      return NextResponse.json(
        { authenticated: false, message: 'No token provided' },
        { status: 401 }
      );
    }
    
    // Verify token
    const decoded = verifyToken(token);
    
    if (!decoded || !decoded.id) {
      return NextResponse.json(
        { authenticated: false, message: 'Invalid token' },
        { status: 401 }
      );
    }
    
    // Get user data with a timeout
    const userId = decoded.id;
    
    try {
      const user = await prisma.user.findUnique({
        where: { id: userId },
        select: {
          id: true,
          email: true,
          role: true,
          organisation_id: true,
          organisation: {
            select: {
              organisation_name: true
            }
          },
          teamMember: {
            select: {
              id: true,
              team_member_name: true
            }
          }
        }
      });
      
      if (!user) {
        return NextResponse.json(
          { authenticated: false, message: 'User not found' },
          { status: 404 }
        );
      }
      
      // Return user data
      return NextResponse.json({
        authenticated: true,
        user: {
          id: user.id,
          email: user.email,
          role: user.role,
          organisation_id: user.organisation_id,
          organisation_name: user.organisation?.organisation_name,
          team_member: user.teamMember
        }
      });
    } catch (dbError) {
      console.error('Database error:', dbError);
      return NextResponse.json(
        { error: 'Database error', message: dbError.message },
        { status: 500 }
      );
    }
  } catch (error) {
    console.error('Error in auth/me route:', error);
    return NextResponse.json(
      { error: 'Server error', message: error.message },
      { status: 500 }
    );
  }
}