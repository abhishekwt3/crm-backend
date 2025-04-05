import prisma from '../../../lib/prisma';
import { verifyToken } from '../../../lib/auth';
import { cookies } from 'next/headers';

export const dynamic = 'force-dynamic';

// Helper to get token from request (checks both Authorization header and cookies)
function getTokenFromRequest(request) {
  // Check Authorization header first
  const authHeader = request.headers.get('authorization');
  if (authHeader && authHeader.startsWith('Bearer ')) {
    return authHeader.substring(7);
  }
  
  // Then check cookies
  const cookieStore = cookies();
  const tokenCookie = cookieStore.get('token');
  
  return tokenCookie?.value;
}

// GET all contacts
export async function GET(request) {
  try {
    // Get token from request
    const token = getTokenFromRequest(request);
    
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
    
    // Get URL parameters for filtering
    const { searchParams } = new URL(request.url);
    const query = searchParams.get('query');
    
    // Build query filter
    let where = {};
    
    // Regular users can only see contacts from their organization
    if (decoded.role !== 'superadmin') {
      where.organisation_id = decoded.organisation_id;
    }
    
    // Add search filter if provided
    if (query) {
      where.OR = [
        { name: { contains: query, mode: 'insensitive' } },
        { email: { contains: query, mode: 'insensitive' } },
        { phone: { contains: query, mode: 'insensitive' } }
      ];
    }
    
    // Fetch contacts
    const contacts = await prisma.contact.findMany({
      where,
      include: {
        organisation: {
          select: {
            organisation_name: true
          }
        },
        properties: {
          select: {
            id: true,
            name: true
          }
        }
      },
      orderBy: {
        name: 'asc'
      }
    });
    
    return new Response(
      JSON.stringify({ contacts }),
      { 
        status: 200,
        headers: { 'Content-Type': 'application/json' }
      }
    );
  } catch (error) {
    console.error('Error in GET /api/contacts:', error);
    return new Response(
      JSON.stringify({ error: 'Internal server error', details: error.message }),
      { 
        status: 500,
        headers: { 'Content-Type': 'application/json' }
      }
    );
  }
}

// POST create new contact
export async function POST(request) {
  try {
    // Get token from request
    const token = getTokenFromRequest(request);
    
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
    if (!data.name) {
      return new Response(
        JSON.stringify({ error: 'Contact name is required' }),
        { 
          status: 400,
          headers: { 'Content-Type': 'application/json' }
        }
      );
    }
    
    // Set organization ID from token if not provided
    if (!data.organisation_id) {
      data.organisation_id = decoded.organisation_id;
    }
    
    // Create new contact
    const contact = await prisma.contact.create({
      data: {
        name: data.name,
        email: data.email,
        phone: data.phone,
        organisation_id: data.organisation_id
      }
    });
    
    return new Response(
      JSON.stringify(contact),
      { 
        status: 201,
        headers: { 'Content-Type': 'application/json' }
      }
    );
  } catch (error) {
    console.error('Error in POST /api/contacts:', error);
    return new Response(
      JSON.stringify({ error: 'Internal server error', details: error.message }),
      { 
        status: 500,
        headers: { 'Content-Type': 'application/json' }
      }
    );
  }
}