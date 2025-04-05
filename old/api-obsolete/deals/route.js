import prisma from '../../../lib/prisma';
import { verifyToken } from '../../../lib/auth';

// GET all deals
export async function GET(request) {
  try {
    // Get token from authorization header
    const authHeader = request.headers.get('authorization');
    const token = authHeader && authHeader.split(' ')[1];
    
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
    
    // Get URL parameters
    const { searchParams } = new URL(request.url);
    const status = searchParams.get('status');
    const assignedTo = searchParams.get('assignedTo');
    
    // Build query filter
    let where = {};
    
    // Filter by organization (based on properties)
    if (decoded.role !== 'superadmin') {
      where.property = {
        organisation_id: decoded.organisation_id
      };
    }
    
    // Add status filter if provided
    if (status) {
      where.status = status;
    }
    
    // Add assignedTo filter if provided
    if (assignedTo) {
      where.assigned_to = parseInt(assignedTo, 10);
    }
    
    // Fetch deals
    const deals = await prisma.deal.findMany({
      where,
      include: {
        property: {
          select: {
            id: true,
            name: true,
            address: true
          }
        },
        assignedTo: {
          select: {
            id: true,
            team_member_name: true
          }
        },
        _count: {
          select: {
            notes: true,
            meetings: true
          }
        }
      },
      orderBy: {
        updated_at: 'desc'
      }
    });
    
    return new Response(
      JSON.stringify({ deals }),
      { 
        status: 200,
        headers: { 'Content-Type': 'application/json' }
      }
    );
  } catch (error) {
    console.error('Error in GET /api/deals:', error);
    return new Response(
      JSON.stringify({ error: 'Internal server error' }),
      { 
        status: 500,
        headers: { 'Content-Type': 'application/json' }
      }
    );
  }
}

// POST create new deal
export async function POST(request) {
  try {
    // Get token from authorization header
    const authHeader = request.headers.get('authorization');
    const token = authHeader && authHeader.split(' ')[1];
    
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
        JSON.stringify({ error: 'Deal name is required' }),
        { 
          status: 400,
          headers: { 'Content-Type': 'application/json' }
        }
      );
    }
    
    if (!data.property_id) {
      return new Response(
        JSON.stringify({ error: 'Property is required' }),
        { 
          status: 400,
          headers: { 'Content-Type': 'application/json' }
        }
      );
    }
    
    // Create new deal
    const deal = await prisma.deal.create({
      data: {
        name: data.name,
        property_id: data.property_id,
        assigned_to: data.assigned_to,
        status: data.status || 'New',
        value: data.value ? parseFloat(data.value) : null
      }
    });
    
    // If there's an initial note, create it
    if (data.initialNote) {
      await prisma.notesThread.create({
        data: {
          deal_id: deal.id,
          comments: data.initialNote,
          team_member_id: decoded.teamMember?.id
        }
      });
    }
    
    return new Response(
      JSON.stringify(deal),
      { 
        status: 201,
        headers: { 'Content-Type': 'application/json' }
      }
    );
  } catch (error) {
    console.error('Error in POST /api/deals:', error);
    return new Response(
      JSON.stringify({ error: 'Internal server error' }),
      { 
        status: 500,
        headers: { 'Content-Type': 'application/json' }
      }
    );
  }
}