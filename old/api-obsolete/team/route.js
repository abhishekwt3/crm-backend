import prisma from '../../../lib/prisma';
import { verifyToken } from '../../../lib/auth';

// GET team members
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
    
    // Check if user has an organization
    if (!decoded.organisation_id) {
      return new Response(
        JSON.stringify({ error: 'User does not belong to an organization' }),
        { 
          status: 400,
          headers: { 'Content-Type': 'application/json' }
        }
      );
    }
    
    // Fetch team members for this organization
    const teamMembers = await prisma.teamMember.findMany({
      where: {
        organisation_id: decoded.organisation_id
      },
      orderBy: {
        id: 'desc'
      }
    });
    
    return new Response(
      JSON.stringify({ teamMembers }),
      { 
        status: 200,
        headers: { 'Content-Type': 'application/json' }
      }
    );
  } catch (error) {
    console.error('Error in GET /api/team:', error);
    return new Response(
      JSON.stringify({ error: 'Internal server error' }),
      { 
        status: 500,
        headers: { 'Content-Type': 'application/json' }
      }
    );
  }
}

// POST create team member
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
    
    // Check if user has an organization
    if (!decoded.organisation_id) {
      return new Response(
        JSON.stringify({ error: 'User does not belong to an organization' }),
        { 
          status: 400,
          headers: { 'Content-Type': 'application/json' }
        }
      );
    }
    
    const data = await request.json();
    
    // Validate required fields
    if (!data.team_member_name || !data.team_member_email_id) {
      return new Response(
        JSON.stringify({ error: 'Name and email are required' }),
        { 
          status: 400,
          headers: { 'Content-Type': 'application/json' }
        }
      );
    }
    
    // Create team member
    const teamMember = await prisma.teamMember.create({
      data: {
        team_member_name: data.team_member_name,
        team_member_email_id: data.team_member_email_id,
        organisation_id: decoded.organisation_id
      }
    });
    
    return new Response(
      JSON.stringify(teamMember),
      { 
        status: 201,
        headers: { 'Content-Type': 'application/json' }
      }
    );
  } catch (error) {
    console.error('Error in POST /api/team:', error);
    return new Response(
      JSON.stringify({ error: 'Internal server error' }),
      { 
        status: 500,
        headers: { 'Content-Type': 'application/json' }
      }
    );
  }
}