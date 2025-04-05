import prisma from '../../../../lib/prisma';
import { verifyToken } from '../../../../lib/auth';

// GET single property by ID
export async function GET(request, { params }) {
  try {
    const { id } = params;
    
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
    
    // Fetch property with related data
    const property = await prisma.property.findUnique({
      where: { id: parseInt(id, 10) },
      include: {
        owner: true,
        organisation: {
          select: {
            id: true,
            organisation_name: true
          }
        },
        _count: {
          select: {
            deals: true,
            documents: true
          }
        }
      }
    });
    
    if (!property) {
      return new Response(
        JSON.stringify({ error: 'Property not found' }),
        { 
          status: 404,
          headers: { 'Content-Type': 'application/json' }
        }
      );
    }
    
    // Check if user has permission to view this property
    if (decoded.role !== 'superadmin' && property.organisation_id !== decoded.organisation_id) {
      return new Response(
        JSON.stringify({ error: 'You do not have permission to view this property' }),
        { 
          status: 403,
          headers: { 'Content-Type': 'application/json' }
        }
      );
    }
    
    return new Response(
      JSON.stringify({ property }),
      { 
        status: 200,
        headers: { 'Content-Type': 'application/json' }
      }
    );
  } catch (error) {
    console.error('Error in GET /api/properties/[id]:', error);
    return new Response(
      JSON.stringify({ error: 'Internal server error' }),
      { 
        status: 500,
        headers: { 'Content-Type': 'application/json' }
      }
    );
  }
}

// PUT update property
export async function PUT(request, { params }) {
  try {
    const { id } = params;
    
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
    
    // Get the property to update
    const existingProperty = await prisma.property.findUnique({
      where: { id: parseInt(id, 10) },
      select: { organisation_id: true }
    });
    
    if (!existingProperty) {
      return new Response(
        JSON.stringify({ error: 'Property not found' }),
        { 
          status: 404,
          headers: { 'Content-Type': 'application/json' }
        }
      );
    }
    
    // Check if user has permission to update this property
    if (decoded.role !== 'superadmin' && existingProperty.organisation_id !== decoded.organisation_id) {
      return new Response(
        JSON.stringify({ error: 'You do not have permission to update this property' }),
        { 
          status: 403,
          headers: { 'Content-Type': 'application/json' }
        }
      );
    }
    
    // Get updated data from request
    const data = await request.json();
    
    // Validate required fields
    if (!data.name) {
      return new Response(
        JSON.stringify({ error: 'Property name is required' }),
        { 
          status: 400,
          headers: { 'Content-Type': 'application/json' }
        }
      );
    }
    
    // Update property
    const property = await prisma.property.update({
      where: { id: parseInt(id, 10) },
      data: {
        name: data.name,
        address: data.address,
        owner_id: data.owner_id ? parseInt(data.owner_id, 10) : null,
        status: data.status
      }
    });
    
    return new Response(
      JSON.stringify({ property }),
      { 
        status: 200,
        headers: { 'Content-Type': 'application/json' }
      }
    );
  } catch (error) {
    console.error('Error in PUT /api/properties/[id]:', error);
    return new Response(
      JSON.stringify({ error: 'Internal server error' }),
      { 
        status: 500,
        headers: { 'Content-Type': 'application/json' }
      }
    );
  }
}

// DELETE property
export async function DELETE(request, { params }) {
  try {
    const { id } = params;
    
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
    
    // Get the property to delete
    const existingProperty = await prisma.property.findUnique({
      where: { id: parseInt(id, 10) },
      select: { organisation_id: true }
    });
    
    if (!existingProperty) {
      return new Response(
        JSON.stringify({ error: 'Property not found' }),
        { 
          status: 404,
          headers: { 'Content-Type': 'application/json' }
        }
      );
    }
    
    // Check if user has permission to delete this property
    if (decoded.role !== 'superadmin' && existingProperty.organisation_id !== decoded.organisation_id) {
      return new Response(
        JSON.stringify({ error: 'You do not have permission to delete this property' }),
        { 
          status: 403,
          headers: { 'Content-Type': 'application/json' }
        }
      );
    }
    
    // Check if property has any associated deals
    const dealsCount = await prisma.deal.count({
      where: { property_id: parseInt(id, 10) }
    });
    
    if (dealsCount > 0) {
      return new Response(
        JSON.stringify({ 
          error: 'Cannot delete property with associated deals', 
          dealsCount 
        }),
        { 
          status: 400,
          headers: { 'Content-Type': 'application/json' }
        }
      );
    }
    
    // Delete property
    await prisma.property.delete({
      where: { id: parseInt(id, 10) }
    });
    
    return new Response(
      JSON.stringify({ success: true, message: 'Property deleted successfully' }),
      { 
        status: 200,
        headers: { 'Content-Type': 'application/json' }
      }
    );
  } catch (error) {
    console.error('Error in DELETE /api/properties/[id]:', error);
    return new Response(
      JSON.stringify({ error: 'Internal server error' }),
      { 
        status: 500,
        headers: { 'Content-Type': 'application/json' }
      }
    );
  }
}