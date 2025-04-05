import prisma from '../../../lib/prisma';
import { verifyToken } from '../../../lib/auth';
import { cookies } from 'next/headers';

// Helper to get token from request (checks both Authorization header and cookies)
async function getTokenFromRequest(request) {
  // Check Authorization header first
  const authHeader = request.headers.get('authorization');
  if (authHeader && authHeader.startsWith('Bearer ')) {
    return authHeader.substring(7);
  }
  
  // Then check cookies
  const cookieStore = await cookies();
  const tokenCookie = cookieStore.get('token');
  
  return tokenCookie?.value;
}

// GET all organizations
export async function GET(request) {
  try {
    // Get token from authorization header
    const token = await getTokenFromRequest(request);
    
    if (!token) {
      return new Response(
        JSON.stringify({ error: 'Authentication required' }),
        { 
          status: 401,
          headers: { 'Content-Type': 'application/json' }
        }
      );
    }
    
    // Verify token
    const decoded = verifyToken(token);
    
    if (!decoded) {
      return new Response(
        JSON.stringify({ error: 'Invalid token' }),
        { 
          status: 401,
          headers: { 'Content-Type': 'application/json' }
        }
      );
    }
    
    // For admin or superadmin roles, might show all organizations
    // For regular users, only show their organization
    let organisations;
    
    if (decoded.role === 'superadmin') {
      organisations = await prisma.organisation.findMany({
        include: {
          _count: {
            select: {
              teamMembers: true,
              properties: true
            }
          }
        }
      });
    } else {
      // Regular users can only see their organization
      organisations = await prisma.organisation.findMany({
        where: {
          id: decoded.organisation_id
        },
        include: {
          _count: {
            select: {
              teamMembers: true,
              properties: true
            }
          }
        }
      });
    }
    
    return new Response(
      JSON.stringify({ organisations }),
      { 
        status: 200,
        headers: { 'Content-Type': 'application/json' }
      }
    );
  } catch (error) {
    console.error('Error in GET /api/organizations:', error);
    return new Response(
      JSON.stringify({ error: 'Internal server error: ' + error.message }),
      { 
        status: 500,
        headers: { 'Content-Type': 'application/json' }
      }
    );
  }
}

// POST create new organization
export async function POST(request) {
  try {
    const token = await getTokenFromRequest(request);
    
    if (!token) {
      return new Response(
        JSON.stringify({ error: 'Authentication required' }),
        { 
          status: 401,
          headers: { 'Content-Type': 'application/json' }
        }
      );
    }
    
    // Verify token
    const decoded = verifyToken(token);
    
    if (!decoded) {
      return new Response(
        JSON.stringify({ error: 'Invalid token' }),
        { 
          status: 401,
          headers: { 'Content-Type': 'application/json' }
        }
      );
    }
    
    const data = await request.json();
    
    // Validate input
    if (!data.organisation_name) {
      return new Response(
        JSON.stringify({ error: 'Organization name is required' }),
        { 
          status: 400,
          headers: { 'Content-Type': 'application/json' }
        }
      );
    }
    
    // Enhanced validation for organisation_name
    if (data.organisation_name.length < 2 || data.organisation_name.length > 50) {
      return new Response(
        JSON.stringify({ error: 'Organization name must be between 2 and 50 characters' }),
        { 
          status: 400,
          headers: { 'Content-Type': 'application/json' }
        }
      );
    }
    
    // Create new organization
    const organisation = await prisma.organisation.create({
      data: {
        organisation_name: data.organisation_name
      }
    });
    
    // Update the user's organization_id if they don't already have one
    if (decoded.id) {
      await prisma.user.update({
        where: { id: decoded.id },
        data: { organisation_id: organisation.id }
      });
      
      // Generate a new token with updated organization info
      const updatedUser = await prisma.user.findUnique({
        where: { id: decoded.id },
        select: {
          id: true,
          email: true,
          role: true,
          organisation_id: organisation.id
        }
      });
      
      // Generate new token
      const { generateToken } = await import('@/lib/auth');
      const newToken = await generateToken(updatedUser);
      
      return new Response(
        JSON.stringify({
          ...organisation,
          token: newToken
        }),
        { 
          status: 201,
          headers: { 'Content-Type': 'application/json' }
        }
      );
    }
    
    return new Response(
      JSON.stringify(organisation),
      { 
        status: 201,
        headers: { 'Content-Type': 'application/json' }
      }
    );
  } catch (error) {
    console.error('Error in POST /api/organizations:', error);
    
    // Handle specific Prisma errors
    if (error.code === 'P2002') {
      return new Response(
        JSON.stringify({ error: 'An organization with this name already exists' }),
        { 
          status: 400,
          headers: { 'Content-Type': 'application/json' }
        }
      );
    }
    
    return new Response(
      JSON.stringify({ error: 'Failed to create organization: ' + error.message }),
      { 
        status: 500,
        headers: { 'Content-Type': 'application/json' }
      }
    );
  }
}