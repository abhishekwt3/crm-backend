import { NextResponse } from 'next/server';
import prisma from '@/lib/prisma';

export const dynamic = 'force-dynamic';

export async function GET() {
  try {
    console.log('Testing database connection...');
    
    // Test if we can connect to the database
    let dbStatus;
    try {
      await prisma.$connect();
      dbStatus = 'connected';
    } catch (connErr) {
      console.error('Connection error:', connErr);
      dbStatus = 'connection failed: ' + connErr.message;
      return NextResponse.json({
        success: false,
        error: 'Database connection failed',
        details: connErr.message
      }, { status: 500 });
    }
    
    // Try to count users
    let userCount;
    try {
      userCount = await prisma.user.count();
      console.log(`Found ${userCount} users`);
    } catch (countErr) {
      console.error('User count error:', countErr);
      return NextResponse.json({
        success: false,
        error: 'Failed to count users',
        details: countErr.message,
        dbStatus
      }, { status: 500 });
    }
    
    // Try to get first user (for testing)
    let firstUser = null;
    if (userCount > 0) {
      try {
        firstUser = await prisma.user.findFirst({
          select: {
            id: true,
            email: true,
            role: true
          }
        });
        console.log('Found first user:', firstUser.email);
      } catch (findErr) {
        console.error('Find user error:', findErr);
        // Continue even if this fails
      }
    }
    
    return NextResponse.json({
      success: true,
      dbStatus,
      userCount,
      firstUser: firstUser ? {
        id: firstUser.id,
        email: firstUser.email,
        role: firstUser.role
      } : null,
      timestamp: new Date().toISOString()
    });
  } catch (error) {
    console.error('Unexpected error in db-test:', error);
    return NextResponse.json({
      success: false,
      error: 'Unexpected error',
      details: error.message
    }, { status: 500 });
  } finally {
    // Make sure we disconnect
    try {
      await prisma.$disconnect();
    } catch (err) {
      console.error('Error disconnecting from database:', err);
    }
  }
}