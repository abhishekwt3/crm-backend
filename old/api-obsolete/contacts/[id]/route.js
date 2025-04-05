import prisma from '../../../../lib/prisma';
import { verifyToken } from '../../../../lib/auth';

// GET a single contact by ID
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
    
    // Find the contact
    const contact = await prisma.contact.findUnique({
      where: { id: parseInt(id, 10) },
      include: {
        organisation: {
          select: {
            id: true,
            organisation_name: true
          }
        },
        properties: {
          select: {
            id: true,
            name: true,
            address: true,
            status: true
          }
        }
      }
    });
    
    if (!contact) {
      return new Response(
        JSON.stringify({ error: 'Contact not found' }),
        { 
          status: 404,
          headers: { 'Content-Type': 'application/json' }
        }
      );
    }
    
    // Check if user has permission to view this contact
    if (decoded.role !== 'superadmin' && contact.organisation_id !== decoded.organisation_id) {
      return new Response(
        JSON.stringify({ error: 'You do not have permission to view this contact' }),
        { 
          status: 403,
          headers: { 'Content-Type': 'application/json' }
        }
      );
    }
    
    return new Response(
      JSON.stringify({ contact }),
      { 
        status: 200,
        headers: { 'Content-Type': 'application/json' }
      }
    );
  } catch (error) {
    console.error('Error in GET /api/contacts/[id]:', error);
    return new Response(
      JSON.stringify({ error: 'Internal server error' }),
      { 
        status: 500,
        headers: { 'Content-Type': 'application/json' }
      }
    );
  }
}

// PUT update contact
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
    
    // Get the contact to update
    const existingContact = await prisma.contact.findUnique({
      where: { id: parseInt(id, 10) },
      select: { organisation_id: true }
    });
    
    if (!existingContact) {
      return new Response(
        JSON.stringify({ error: 'Contact not found' }),
        { 
          status: 404,
          headers: { 'Content-Type': 'application/json' }
        }
      );
    }
    
    // Check if user has permission to update this contact
    if (decoded.role !== 'superadmin' && existingContact.organisation_id !== decoded.organisation_id) {
      return new Response(
        JSON.stringify({ error: 'You do not have permission to update this contact' }),
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
        JSON.stringify({ error: 'Contact name is required' }),
        { 
          status: 400,
          headers: { 'Content-Type': 'application/json' }
        }
      );
    }
    
    // Update contact
    const contact = await prisma.contact.update({
      where: { id: parseInt(id, 10) },
      data: {
        name: data.name,
        email: data.email,
        phone: data.phone,
        organisation_id: data.organisation_id ? parseInt(data.organisation_id, 10) : undefined
      }
    });
    
    return new Response(
      JSON.stringify({ contact }),
      { 
        status: 200,
        headers: { 'Content-Type': 'application/json' }
      }
    );
  } catch (error) {
    console.error('Error in PUT /api/contacts/[id]:', error);
    return new Response(
      JSON.stringify({ error: 'Internal server error' }),
      { 
        status: 500,
        headers: { 'Content-Type': 'application/json' }
      }
    );
  }
}

// DELETE contact
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
    
    // Get the contact to delete
    const existingContact = await prisma.contact.findUnique({
      where: { id: parseInt(id, 10) },
      include: {
        properties: {
          select: { id: true }
        }
      }
    });
    
    if (!existingContact) {
      return new Response(
        JSON.stringify({ error: 'Contact not found' }),
        { 
          status: 404,
          headers: { 'Content-Type': 'application/json' }
        }
      );
    }
    
    // Check if user has permission to delete this contact
    if (decoded.role !== 'superadmin' && existingContact.organisation_id !== decoded.organisation_id) {
      return new Response(
        JSON.stringify({ error: 'You do not have permission to delete this contact' }),
        { 
          status: 403,
          headers: { 'Content-Type': 'application/json' }
        }
      );
    }
    
    // Check if contact has associated properties
    if (existingContact.properties.length > 0) {
      return new Response(
        JSON.stringify({ 
          error: 'Cannot delete contact with associated properties. Update the property owners first.',
          propertyCount: existingContact.properties.length
        }),
        { 
          status: 400,
          headers: { 'Content-Type': 'application/json' }
        }
      );
    }
    
    // Delete contact
    await prisma.contact.delete({
      where: { id: parseInt(id, 10) }
    });
    
    return new Response(
      JSON.stringify({ success: true, message: 'Contact deleted successfully' }),
      { 
        status: 200,
        headers: { 'Content-Type': 'application/json' }
      }
    );
  } catch (error) {
    console.error('Error in DELETE /api/contacts/[id]:', error);
    return new Response(
      JSON.stringify({ error: 'Internal server error' }),
      { 
        status: 500,
        headers: { 'Content-Type': 'application/json' }
      }
    );
  }
}