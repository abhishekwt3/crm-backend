const express = require('express');
const { PrismaClient } = require('@prisma/client');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const dotenv = require('dotenv');

// Initialize environment variables
dotenv.config();

// Initialize Express app
const app = express();
const prisma = new PrismaClient();
const PORT = process.env.PORT || 3001;
const JWT_SECRET = process.env.JWT_SECRET || 'default-secret-key-change-in-production';

// Middleware
app.use(cors());
app.use(express.json());

// Authentication middleware
const authenticateToken = async (req, res, next) => {
  try {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];
    
    if (!token) {
      return res.status(401).json({ error: 'Authentication required' });
    }
    
    jwt.verify(token, JWT_SECRET, (err, decoded) => {
      if (err) {
        return res.status(401).json({ error: 'Invalid token' });
      }
      
      req.user = decoded;
      next();
    });
  } catch (error) {
    console.error('Auth middleware error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
};

// AUTH ROUTES

// Register
app.post('/api/auth/register', async (req, res) => {
  try {
    const { email, password, role = 'admin' } = req.body;
    
    // Validate input
    if (!email || !password) {
      return res.status(400).json({ error: 'Email and password are required' });
    }
    
    // Check if user exists
    const existingUser = await prisma.user.findUnique({
      where: { email }
    });
    
    if (existingUser) {
      return res.status(400).json({ error: 'Email already exists' });
    }
    
    // Hash password
    const hashedPassword = await bcrypt.hash(password, 10);
    
    // Create user
    const user = await prisma.user.create({
      data: {
        email,
        password: hashedPassword,
        role
      }
    });
    
    // Generate token
    const token = jwt.sign(
      { id: user.id, email: user.email, role: user.role },
      JWT_SECRET,
      { expiresIn: '7d' }
    );
    
    res.status(201).json({
      success: true,
      user: {
        id: user.id,
        email: user.email,
        role: user.role
      },
      token,
      setupRequired: true,
      nextStep: 'create-organization'
    });
  } catch (error) {
    console.error('Registration error:', error);
    res.status(500).json({ error: 'Registration failed' });
  }
});

// Login
app.post('/api/auth/login', async (req, res) => {
  try {
    const { email, password } = req.body;
    
    // Validate input
    if (!email || !password) {
      return res.status(400).json({ error: 'Email and password are required' });
    }
    
    // Find user
    const user = await prisma.user.findUnique({
      where: { email },
      include: {
        organisation: {
          select: {
            id: true,
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
      return res.status(401).json({ error: 'Invalid email or password' });
    }
    
    // Verify password
    const isPasswordValid = await bcrypt.compare(password, user.password);
    
    if (!isPasswordValid) {
      return res.status(401).json({ error: 'Invalid email or password' });
    }
    
    // Generate token
    const token = jwt.sign(
      { 
        id: user.id, 
        email: user.email, 
        role: user.role,
        organisation_id: user.organisation_id,
        teamMember: user.teamMember ? {
          id: user.teamMember.id,
          name: user.teamMember.team_member_name
        } : null
      },
      JWT_SECRET,
      { expiresIn: '7d' }
    );
    
    res.status(200).json({
      success: true,
      user: {
        id: user.id,
        email: user.email,
        role: user.role,
        organisation_id: user.organisation_id,
        organisation_name: user.organisation?.organisation_name,
        team_member: user.teamMember
      },
      token
    });
  } catch (error) {
    console.error('Login error:', error);
    res.status(500).json({ error: 'Login failed' });
  }
});

// Get current user
app.get('/api/auth/me', authenticateToken, async (req, res) => {
  try {
    const userId = req.user.id;
    
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
      return res.status(404).json({ 
        authenticated: false, 
        message: 'User not found' 
      });
    }
    
    res.status(200).json({
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
  } catch (error) {
    console.error('Get user error:', error);
    res.status(500).json({ error: 'Failed to get user data' });
  }
});

// Express backend route for /api/auth/me

app.get('/api/auth/me', (req, res) => {
  try {
    // Get token from authorization header
    const authHeader = req.headers.authorization;
    
    if (!authHeader || !authHeader.startsWith('Bearer ')) {
      return res.status(401).json({ 
        authenticated: false, 
        message: 'No token provided' 
      });
    }
    
    const token = authHeader.substring(7);
    
    // Verify token
    jwt.verify(token, JWT_SECRET, async (err, decoded) => {
      if (err) {
        return res.status(401).json({ 
          authenticated: false, 
          message: 'Invalid token' 
        });
      }
      
      try {
        // Get user data
        const user = await prisma.user.findUnique({
          where: { id: decoded.id },
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
          return res.status(404).json({ 
            authenticated: false, 
            message: 'User not found' 
          });
        }
        
        // Return user data
        res.json({
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
        res.status(500).json({ 
          error: 'Database error', 
          message: dbError.message 
        });
      }
    });
  } catch (error) {
    console.error('Error in auth/me route:', error);
    res.status(500).json({ 
      error: 'Server error', 
      message: error.message 
    });
  }
});

// Logout - simply a placeholder since JWT management is handled client-side
app.post('/api/auth/logout', (req, res) => {
  res.status(200).json({ 
    success: true,
    message: 'Logged out successfully' 
  });
});

// ORGANIZATION ROUTES

// Get all organizations
app.get('/api/organizations', authenticateToken, async (req, res) => {
  try {
    let organisations;
    
    // For admin or superadmin roles, might show all organizations
    // For regular users, only show their organization
    if (req.user.role === 'superadmin') {
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
          id: req.user.organisation_id
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
    
    res.status(200).json({ organisations });
  } catch (error) {
    console.error('Get organizations error:', error);
    res.status(500).json({ error: 'Failed to fetch organizations' });
  }
});

// Create organization
app.post('/api/organizations', authenticateToken, async (req, res) => {
  try {
    const { organisation_name } = req.body;
    
    // Validate input
    if (!organisation_name) {
      return res.status(400).json({ error: 'Organization name is required' });
    }
    
    // Create organization
    const organisation = await prisma.organisation.create({
      data: {
        organisation_name
      }
    });
    
    // Update the user's organization
    await prisma.user.update({
      where: { id: req.user.id },
      data: { organisation_id: organisation.id }
    });
    
    res.status(201).json(organisation);
  } catch (error) {
    console.error('Create organization error:', error);
    
    // Handle specific Prisma errors
    if (error.code === 'P2002') {
      return res.status(400).json({ error: 'An organization with this name already exists' });
    }
    
    res.status(500).json({ error: 'Failed to create organization' });
  }
});

// Get organization by ID
app.get('/api/organizations/:id', authenticateToken, async (req, res) => {
  try {
    const { id } = req.params;
    
    // Check if user has access to this organization
    if (req.user.role !== 'superadmin' && req.user.organisation_id !== parseInt(id)) {
      return res.status(403).json({ error: 'You do not have permission to view this organization' });
    }
    
    const organisation = await prisma.organisation.findUnique({
      where: { id: parseInt(id) },
      include: {
        teamMembers: true,
        properties: true
      }
    });
    
    if (!organisation) {
      return res.status(404).json({ error: 'Organization not found' });
    }
    
    res.status(200).json({ organisation });
  } catch (error) {
    console.error('Get organization error:', error);
    res.status(500).json({ error: 'Failed to fetch organization' });
  }
});

// Update organization
app.put('/api/organizations/:id', authenticateToken, async (req, res) => {
  try {
    const { id } = req.params;
    const { organisation_name } = req.body;
    
    // Check if user has access to this organization
    if (req.user.role !== 'superadmin' && req.user.organisation_id !== parseInt(id)) {
      return res.status(403).json({ error: 'You do not have permission to update this organization' });
    }
    
    // Validate input
    if (!organisation_name) {
      return res.status(400).json({ error: 'Organization name is required' });
    }
    
    const organisation = await prisma.organisation.update({
      where: { id: parseInt(id) },
      data: { organisation_name }
    });
    
    res.status(200).json(organisation);
  } catch (error) {
    console.error('Update organization error:', error);
    res.status(500).json({ error: 'Failed to update organization' });
  }
});

// Delete organization
app.delete('/api/organizations/:id', authenticateToken, async (req, res) => {
  try {
    const { id } = req.params;
    
    // Only superadmins can delete organizations
    if (req.user.role !== 'superadmin') {
      return res.status(403).json({ error: 'You do not have permission to delete organizations' });
    }
    
    // Check for associated data
    const [teamMembersCount, propertiesCount] = await Promise.all([
      prisma.teamMember.count({ where: { organisation_id: parseInt(id) } }),
      prisma.property.count({ where: { organisation_id: parseInt(id) } })
    ]);
    
    if (teamMembersCount > 0 || propertiesCount > 0) {
      return res.status(400).json({ 
        error: 'Cannot delete organization with associated team members or properties',
        teamMembersCount,
        propertiesCount
      });
    }
    
    await prisma.organisation.delete({
      where: { id: parseInt(id) }
    });
    
    res.status(200).json({ 
      success: true, 
      message: 'Organization deleted successfully' 
    });
  } catch (error) {
    console.error('Delete organization error:', error);
    res.status(500).json({ error: 'Failed to delete organization' });
  }
});

// TEAM MEMBER ROUTES

// Get all team members
app.get('/api/team', authenticateToken, async (req, res) => {
  try {
    // First check if the user has an organization
    if (!req.user.organisation_id) {
      return res.status(400).json({ 
        error: 'You must belong to an organization before managing team members',
        code: 'NO_ORGANIZATION' 
      });
    }
    
    let teamMembers;
    
    if (req.user.role === 'superadmin') {
      teamMembers = await prisma.teamMember.findMany({
        include: {
          organisation: {
            select: {
              organisation_name: true
            }
          },
          user: {
            select: {
              id: true,
              email: true,
              role: true
            }
          }
        }
      });
    } else {
      teamMembers = await prisma.teamMember.findMany({
        where: {
          organisation_id: req.user.organisation_id
        },
        include: {
          organisation: {
            select: {
              organisation_name: true
            }
          },
          user: {
            select: {
              id: true,
              email: true,
              role: true
            }
          }
        }
      });
    }
    
    // Return empty array rather than error if no team members found
    res.status(200).json({ teamMembers });
  } catch (error) {
    console.error('Get team members error:', error);
    res.status(500).json({ error: 'Failed to fetch team members' });
  }
});

// Create team member
app.post('/api/team', authenticateToken, async (req, res) => {
  try {
    const { team_member_name, team_member_email_id } = req.body;
    
    // Validate input
    if (!team_member_name || !team_member_email_id) {
      return res.status(400).json({ error: 'Name and email are required' });
    }
    
    // Set organization from current user if not provided
    const organisation_id = req.body.organisation_id || req.user.organisation_id;
    
    // Check if user can create team members for this organization
    if (req.user.role !== 'superadmin' && req.user.organisation_id !== organisation_id) {
      return res.status(403).json({ error: 'You do not have permission to add team members to this organization' });
    }
    
    const teamMember = await prisma.teamMember.create({
      data: {
        team_member_name,
        team_member_email_id,
        organisation_id
      }
    });
    
    res.status(201).json(teamMember);
  } catch (error) {
    console.error('Create team member error:', error);
    res.status(500).json({ error: 'Failed to create team member' });
  }
});

// Get team member by ID
app.get('/api/team/:id', authenticateToken, async (req, res) => {
  try {
    const { id } = req.params;
    
    // Check if ID is a valid number
    const memberId = parseInt(id);
    if (isNaN(memberId)) {
      return res.status(400).json({ error: 'Invalid team member ID' });
    }
    
    const teamMember = await prisma.teamMember.findUnique({
      where: { id: memberId },
      include: {
        organisation: {
          select: {
            organisation_name: true
          }
        },
        user: {
          select: {
            id: true,
            email: true,
            role: true
          }
        }
      }
    });
    
    if (!teamMember) {
      return res.status(404).json({ error: 'Team member not found' });
    }
    
    // Check if user has access to this team member
    if (req.user.role !== 'superadmin' && req.user.organisation_id !== teamMember.organisation_id) {
      return res.status(403).json({ error: 'You do not have permission to view this team member' });
    }
    
    res.status(200).json({ teamMember });
  } catch (error) {
    console.error('Get team member error:', error);
    res.status(500).json({ error: 'Failed to fetch team member' });
  }
});

// Update team member
app.put('/api/team/:id', authenticateToken, async (req, res) => {
  try {
    const { id } = req.params;
    const { team_member_name, team_member_email_id } = req.body;
    
    // Get the team member to check permissions
    const existingTeamMember = await prisma.teamMember.findUnique({
      where: { id: parseInt(id) },
      select: { organisation_id: true }
    });
    
    if (!existingTeamMember) {
      return res.status(404).json({ error: 'Team member not found' });
    }
    
    // Check if user has access to this team member
    if (req.user.role !== 'superadmin' && req.user.organisation_id !== existingTeamMember.organisation_id) {
      return res.status(403).json({ error: 'You do not have permission to update this team member' });
    }
    
    const teamMember = await prisma.teamMember.update({
      where: { id: parseInt(id) },
      data: {
        team_member_name,
        team_member_email_id
      }
    });
    
    res.status(200).json(teamMember);
  } catch (error) {
    console.error('Update team member error:', error);
    res.status(500).json({ error: 'Failed to update team member' });
  }
});

// Delete team member
app.delete('/api/team/:id', authenticateToken, async (req, res) => {
  try {
    const { id } = req.params;
    
    // Get the team member to check permissions
    const existingTeamMember = await prisma.teamMember.findUnique({
      where: { id: parseInt(id) },
      select: { 
        organisation_id: true,
        _count: {
          select: {
            deals: true,
            discussions: true,
            meetings: true
          }
        }
      }
    });
    
    if (!existingTeamMember) {
      return res.status(404).json({ error: 'Team member not found' });
    }
    
    // Check if user has access to this team member
    if (req.user.role !== 'superadmin' && req.user.organisation_id !== existingTeamMember.organisation_id) {
      return res.status(403).json({ error: 'You do not have permission to delete this team member' });
    }
    
    // Check for associated data
    const totalAssociations = 
      existingTeamMember._count.deals + 
      existingTeamMember._count.discussions + 
      existingTeamMember._count.meetings;
    
    if (totalAssociations > 0) {
      return res.status(400).json({ 
        error: 'Cannot delete team member with associated deals, discussions, or meetings',
        associations: {
          deals: existingTeamMember._count.deals,
          discussions: existingTeamMember._count.discussions,
          meetings: existingTeamMember._count.meetings
        }
      });
    }
    
    await prisma.teamMember.delete({
      where: { id: parseInt(id) }
    });
    
    res.status(200).json({ 
      success: true, 
      message: 'Team member deleted successfully' 
    });
  } catch (error) {
    console.error('Delete team member error:', error);
    res.status(500).json({ error: 'Failed to delete team member' });
  }
});

// CONTACT ROUTES

// Get all contacts
app.get('/api/contacts', authenticateToken, async (req, res) => {
  try {
    const { query } = req.query;
    
    // Build query filter
    let where = {};
    
    // Regular users can only see contacts from their organization
    if (req.user.role !== 'superadmin') {
      where.organisation_id = req.user.organisation_id;
    }
    
    // Add search filter if provided
    if (query) {
      where.OR = [
        { name: { contains: query, mode: 'insensitive' } },
        { email: { contains: query, mode: 'insensitive' } },
        { phone: { contains: query, mode: 'insensitive' } }
      ];
    }
    
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
    
    res.status(200).json({ contacts });
  } catch (error) {
    console.error('Get contacts error:', error);
    res.status(500).json({ error: 'Failed to fetch contacts' });
  }
});

// Create contact
app.post('/api/contacts', authenticateToken, async (req, res) => {
  try {
    const { name, email, phone, organisation_id } = req.body;
    
    // Validate input
    if (!name) {
      return res.status(400).json({ error: 'Contact name is required' });
    }
    
    // Set organization from current user if not provided
    const orgId = organisation_id || req.user.organisation_id;
    
    const contact = await prisma.contact.create({
      data: {
        name,
        email,
        phone,
        organisation_id: orgId
      }
    });
    
    res.status(201).json(contact);
  } catch (error) {
    console.error('Create contact error:', error);
    res.status(500).json({ error: 'Failed to create contact' });
  }
});

// Get contact by ID
app.get('/api/contacts/:id', authenticateToken, async (req, res) => {
  try {
    const { id } = req.params;
    
    const contact = await prisma.contact.findUnique({
      where: { id: parseInt(id) },
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
      return res.status(404).json({ error: 'Contact not found' });
    }
    
    // Check if user has permission to view this contact
    if (req.user.role !== 'superadmin' && contact.organisation_id !== req.user.organisation_id) {
      return res.status(403).json({ error: 'You do not have permission to view this contact' });
    }
    
    res.status(200).json({ contact });
  } catch (error) {
    console.error('Get contact error:', error);
    res.status(500).json({ error: 'Failed to fetch contact' });
  }
});

// Update contact
app.put('/api/contacts/:id', authenticateToken, async (req, res) => {
  try {
    const { id } = req.params;
    const { name, email, phone, organisation_id } = req.body;
    
    // Get the contact to update to check permissions
    const existingContact = await prisma.contact.findUnique({
      where: { id: parseInt(id) },
      select: { organisation_id: true }
    });
    
    if (!existingContact) {
      return res.status(404).json({ error: 'Contact not found' });
    }
    
    // Check if user has permission to update this contact
    if (req.user.role !== 'superadmin' && existingContact.organisation_id !== req.user.organisation_id) {
      return res.status(403).json({ error: 'You do not have permission to update this contact' });
    }
    
    // Validate required fields
    if (!name) {
      return res.status(400).json({ error: 'Contact name is required' });
    }
    
    // Update contact
    const contact = await prisma.contact.update({
      where: { id: parseInt(id) },
      data: {
        name,
        email,
        phone,
        organisation_id: organisation_id ? parseInt(organisation_id) : undefined
      }
    });
    
    res.status(200).json({ contact });
  } catch (error) {
    console.error('Update contact error:', error);
    res.status(500).json({ error: 'Failed to update contact' });
  }
});

// Delete contact
app.delete('/api/contacts/:id', authenticateToken, async (req, res) => {
  try {
    const { id } = req.params;
    
    // Get the contact to delete to check permissions and relationships
    const existingContact = await prisma.contact.findUnique({
      where: { id: parseInt(id) },
      include: {
        properties: {
          select: { id: true }
        }
      }
    });
    
    if (!existingContact) {
      return res.status(404).json({ error: 'Contact not found' });
    }
    
    // Check if user has permission to delete this contact
    if (req.user.role !== 'superadmin' && existingContact.organisation_id !== req.user.organisation_id) {
      return res.status(403).json({ error: 'You do not have permission to delete this contact' });
    }
    
    // Check if contact has associated properties
    if (existingContact.properties.length > 0) {
      return res.status(400).json({ 
        error: 'Cannot delete contact with associated properties. Update the property owners first.',
        propertyCount: existingContact.properties.length
      });
    }
    
    // Delete contact
    await prisma.contact.delete({
      where: { id: parseInt(id) }
    });
    
    res.status(200).json({ 
      success: true, 
      message: 'Contact deleted successfully' 
    });
  } catch (error) {
    console.error('Delete contact error:', error);
    res.status(500).json({ error: 'Failed to delete contact' });
  }
});

// PROPERTY ROUTES

// Get all properties
app.get('/api/properties', authenticateToken, async (req, res) => {
  try {
    const { status } = req.query;
    
    // Build query filter based on user role and optional filters
    let where = {};
    
    // Regular users can only see properties from their organization
    if (req.user.role !== 'superadmin') {
      where.organisation_id = req.user.organisation_id;
    }
    
    // Add status filter if provided
    if (status) {
      where.status = status;
    }
    
    // Fetch properties
    const properties = await prisma.property.findMany({
      where,
      include: {
        owner: true,
        organisation: {
          select: {
            organisation_name: true
          }
        },
        _count: {
          select: {
            deals: true
          }
        }
      }
    });
    
    res.status(200).json({ properties });
  } catch (error) {
    console.error('Get properties error:', error);
    res.status(500).json({ error: 'Failed to fetch properties' });
  }
});

// Create property
app.post('/api/properties', authenticateToken, async (req, res) => {
  try {
    const { name, address, owner_id, status = 'Available' } = req.body;
    
    // Validate input
    if (!name) {
      return res.status(400).json({ error: 'Property name is required' });
    }
    
    // Set organization ID from token if not provided
    const organisation_id = req.body.organisation_id || req.user.organisation_id;
    
    // Create new property
    const property = await prisma.property.create({
      data: {
        name,
        address,
        owner_id: owner_id ? parseInt(owner_id) : null,
        organisation_id,
        status
      }
    });
    
    res.status(201).json(property);
  } catch (error) {
    console.error('Create property error:', error);
    res.status(500).json({ error: 'Failed to create property' });
  }
});

// Get property by ID
app.get('/api/properties/:id', authenticateToken, async (req, res) => {
  try {
    const { id } = req.params;
    
    // Fetch property with related data
    const property = await prisma.property.findUnique({
      where: { id: parseInt(id) },
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
      return res.status(404).json({ error: 'Property not found' });
    }
    
    // Check if user has permission to view this property
    if (req.user.role !== 'superadmin' && property.organisation_id !== req.user.organisation_id) {
      return res.status(403).json({ error: 'You do not have permission to view this property' });
    }
    
    res.status(200).json({ property });
  } catch (error) {
    console.error('Get property error:', error);
    res.status(500).json({ error: 'Failed to fetch property' });
  }
});

// Update property
app.put('/api/properties/:id', authenticateToken, async (req, res) => {
  try {
    const { id } = req.params;
    const { name, address, owner_id, status } = req.body;
    
    // Get the property to update
    const existingProperty = await prisma.property.findUnique({
      where: { id: parseInt(id) },
      select: { organisation_id: true }
    });
    
    if (!existingProperty) {
      return res.status(404).json({ error: 'Property not found' });
    }
    
    // Check if user has permission to update this property
    if (req.user.role !== 'superadmin' && existingProperty.organisation_id !== req.user.organisation_id) {
      return res.status(403).json({ error: 'You do not have permission to update this property' });
    }
    
    // Validate required fields
    if (!name) {
      return res.status(400).json({ error: 'Property name is required' });
    }
    
    // Update property
    const property = await prisma.property.update({
      where: { id: parseInt(id) },
      data: {
        name,
        address,
        owner_id: owner_id ? parseInt(owner_id) : null,
        status
      }
    });

res.status(200).json({ property });
} catch (error) {
console.error('Update property error:', error);
res.status(500).json({ error: 'Failed to update property' });
}
});

// Delete property
app.delete('/api/properties/:id', authenticateToken, async (req, res) => {
try {
const { id } = req.params;

// Get the property to delete
const existingProperty = await prisma.property.findUnique({
where: { id: parseInt(id) },
select: { organisation_id: true }
});

if (!existingProperty) {
return res.status(404).json({ error: 'Property not found' });
}

// Check if user has permission to delete this property
if (req.user.role !== 'superadmin' && existingProperty.organisation_id !== req.user.organisation_id) {
return res.status(403).json({ error: 'You do not have permission to delete this property' });
}

// Check if property has any associated deals
const dealsCount = await prisma.deal.count({
where: { property_id: parseInt(id) }
});

if (dealsCount > 0) {
return res.status(400).json({ 
  error: 'Cannot delete property with associated deals', 
  dealsCount 
});
}

// Delete property
await prisma.property.delete({
where: { id: parseInt(id) }
});

res.status(200).json({ 
success: true, 
message: 'Property deleted successfully' 
});
} catch (error) {
console.error('Delete property error:', error);
res.status(500).json({ error: 'Failed to delete property' });
}
});

// DEAL ROUTES

// Get all deals
app.get('/api/deals', authenticateToken, async (req, res) => {
try {
const { status, assignedTo, property_id } = req.query;

// Build query filter
let where = {};

// Filter by organization (based on properties)
if (req.user.role !== 'superadmin') {
where.property = {
  organisation_id: req.user.organisation_id
};
}

// Add status filter if provided
if (status) {
where.status = status;
}

// Add assignedTo filter if provided
if (assignedTo) {
where.assigned_to = parseInt(assignedTo);
}

// Add property filter if provided
if (property_id) {
where.property_id = parseInt(property_id);
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
      discussions: true,
      meetings: true
    }
  }
},
orderBy: {
  updated_at: 'desc'
}
});

res.status(200).json({ deals });
} catch (error) {
console.error('Get deals error:', error);
res.status(500).json({ error: 'Failed to fetch deals' });
}
});

// Create deal
app.post('/api/deals', authenticateToken, async (req, res) => {
try {
const { name, property_id, assigned_to, status = 'New', value, initialNote } = req.body;

// Validate input
if (!name) {
return res.status(400).json({ error: 'Deal name is required' });
}

if (!property_id) {
return res.status(400).json({ error: 'Property is required' });
}

// Check if user has access to the property's organization
const property = await prisma.property.findUnique({
where: { id: parseInt(property_id) },
select: { organisation_id: true }
});

if (!property) {
return res.status(404).json({ error: 'Property not found' });
}

if (req.user.role !== 'superadmin' && property.organisation_id !== req.user.organisation_id) {
return res.status(403).json({ error: 'You do not have permission to create deals for this property' });
}

// Create new deal
const deal = await prisma.deal.create({
data: {
  name,
  property_id: parseInt(property_id),
  assigned_to: assigned_to ? parseInt(assigned_to) : null,
  status,
  value: value ? parseFloat(value) : null
}
});

// If there's an initial note, create it
if (initialNote) {
await prisma.discussion.create({
  data: {
    deal_id: deal.id,
    comments: initialNote,
    team_member_id: req.user.teamMember?.id || null
  }
});
}

res.status(201).json(deal);
} catch (error) {
console.error('Create deal error:', error);
res.status(500).json({ error: 'Failed to create deal' });
}
});

// Get deal by ID
app.get('/api/deals/:id', authenticateToken, async (req, res) => {
try {
const { id } = req.params;

const deal = await prisma.deal.findUnique({
where: { id: parseInt(id) },
include: {
  property: {
    select: {
      id: true,
      name: true,
      address: true,
      organisation_id: true
    }
  },
  assignedTo: {
    select: {
      id: true,
      team_member_name: true
    }
  },
  discussions: {
    include: {
      teamMember: {
        select: {
          id: true,
          team_member_name: true
        }
      }
    },
    orderBy: {
      timestamp: 'desc'
    }
  },
  meetings: {
    include: {
      teamMember: {
        select: {
          id: true,
          team_member_name: true
        }
      }
    },
    orderBy: {
      datetime: 'desc'
    }
  }
}
});

if (!deal) {
return res.status(404).json({ error: 'Deal not found' });
}

// Check if user has permission to view this deal
if (req.user.role !== 'superadmin' && deal.property.organisation_id !== req.user.organisation_id) {
return res.status(403).json({ error: 'You do not have permission to view this deal' });
}

res.status(200).json({ deal });
} catch (error) {
console.error('Get deal error:', error);
res.status(500).json({ error: 'Failed to fetch deal' });
}
});

// Update deal
app.put('/api/deals/:id', authenticateToken, async (req, res) => {
try {
const { id } = req.params;
const { name, property_id, assigned_to, status, value } = req.body;

// Get the deal to update
const existingDeal = await prisma.deal.findUnique({
where: { id: parseInt(id) },
include: {
  property: {
    select: { organisation_id: true }
  }
}
});

if (!existingDeal) {
return res.status(404).json({ error: 'Deal not found' });
}

// Check if user has permission to update this deal
if (req.user.role !== 'superadmin' && existingDeal.property.organisation_id !== req.user.organisation_id) {
return res.status(403).json({ error: 'You do not have permission to update this deal' });
}

// If changing property, check if user has access to the new property's organization
if (property_id && property_id !== existingDeal.property_id) {
const newProperty = await prisma.property.findUnique({
  where: { id: parseInt(property_id) },
  select: { organisation_id: true }
});

if (!newProperty) {
  return res.status(404).json({ error: 'Property not found' });
}

if (req.user.role !== 'superadmin' && newProperty.organisation_id !== req.user.organisation_id) {
  return res.status(403).json({ error: 'You do not have permission to assign deals to this property' });
}
}

// Update deal
const deal = await prisma.deal.update({
where: { id: parseInt(id) },
data: {
  name,
  property_id: property_id ? parseInt(property_id) : undefined,
  assigned_to: assigned_to ? parseInt(assigned_to) : null,
  status,
  value: value ? parseFloat(value) : null
}
});

res.status(200).json({ deal });
} catch (error) {
console.error('Update deal error:', error);
res.status(500).json({ error: 'Failed to update deal' });
}
});

// Delete deal
app.delete('/api/deals/:id', authenticateToken, async (req, res) => {
try {
const { id } = req.params;

// Get the deal to delete
const existingDeal = await prisma.deal.findUnique({
where: { id: parseInt(id) },
include: {
  property: {
    select: { organisation_id: true }
  },
  _count: {
    select: {
      discussions: true,
      meetings: true
    }
  }
}
});

if (!existingDeal) {
return res.status(404).json({ error: 'Deal not found' });
}

// Check if user has permission to delete this deal
if (req.user.role !== 'superadmin' && existingDeal.property.organisation_id !== req.user.organisation_id) {
return res.status(403).json({ error: 'You do not have permission to delete this deal' });
}

// Check if deal has associated discussions or meetings
const totalAssociations = existingDeal._count.discussions + existingDeal._count.meetings;

if (totalAssociations > 0) {
return res.status(400).json({ 
  error: 'Cannot delete deal with associated discussions or meetings. Delete them first.',
  associations: {
    discussions: existingDeal._count.discussions,
    meetings: existingDeal._count.meetings
  }
});
}

// Delete deal
await prisma.deal.delete({
where: { id: parseInt(id) }
});

res.status(200).json({ 
success: true, 
message: 'Deal deleted successfully' 
});
} catch (error) {
console.error('Delete deal error:', error);
res.status(500).json({ error: 'Failed to delete deal' });
}
});

// DISCUSSIONS ROUTES

// Get all discussions for a deal
app.get('/api/deals/:dealId/discussions', authenticateToken, async (req, res) => {
  try {
    const { dealId } = req.params;

    // Check if user has permission to view discussions for this deal
    const deal = await prisma.deal.findUnique({
      where: { id: parseInt(dealId) },
      include: {
        property: {
          select: { organisation_id: true }
        }
      }
    });

    if (!deal) {
      return res.status(404).json({ error: 'Deal not found' });
    }

    if (req.user.role !== 'superadmin' && deal.property.organisation_id !== req.user.organisation_id) {
      return res.status(403).json({ error: 'You do not have permission to view discussions for this deal' });
    }

    // Fetch discussions
    const discussions = await prisma.discussion.findMany({
      where: { deal_id: parseInt(dealId) },
      include: {
        teamMember: {
          select: {
            id: true,
            team_member_name: true
          }
        }
      },
      orderBy: {
        timestamp: 'desc'
      }
    });

    res.status(200).json({ discussions });
  } catch (error) {
    console.error('Get discussions error:', error);
    res.status(500).json({ error: 'Failed to fetch discussions' });
  }
});

// Create discussion for a deal
app.post('/api/deals/:dealId/discussions', authenticateToken, async (req, res) => {
  try {
    const { dealId } = req.params;
    const { comments } = req.body;

    // Validate input
    if (!comments) {
      return res.status(400).json({ error: 'Comments are required' });
    }

    // Check if user has permission to add discussions to this deal
    const deal = await prisma.deal.findUnique({
      where: { id: parseInt(dealId) },
      include: {
        property: {
          select: { organisation_id: true }
        }
      }
    });

    if (!deal) {
      return res.status(404).json({ error: 'Deal not found' });
    }

    if (req.user.role !== 'superadmin' && deal.property.organisation_id !== req.user.organisation_id) {
      return res.status(403).json({ error: 'You do not have permission to add discussions to this deal' });
    }

    // Create discussion
    const discussion = await prisma.discussion.create({
      data: {
        deal_id: parseInt(dealId),
        comments,
        team_member_id: req.user.teamMember?.id || null
      }
    });

    res.status(201).json(discussion);
  } catch (error) {
    console.error('Create discussion error:', error);
    res.status(500).json({ error: 'Failed to create discussion' });
  }
});

// MEETINGS ROUTES

// Get all meetings for a deal
app.get('/api/deals/:dealId/meetings', authenticateToken, async (req, res) => {
try {
const { dealId } = req.params;

// Check if user has permission to view meetings for this deal
const deal = await prisma.deal.findUnique({
where: { id: parseInt(dealId) },
include: {
  property: {
    select: { organisation_id: true }
  }
}
});

if (!deal) {
return res.status(404).json({ error: 'Deal not found' });
}

if (req.user.role !== 'superadmin' && deal.property.organisation_id !== req.user.organisation_id) {
return res.status(403).json({ error: 'You do not have permission to view meetings for this deal' });
}

// Fetch meetings
const meetings = await prisma.meeting.findMany({
where: { deal_id: parseInt(dealId) },
include: {
  teamMember: {
    select: {
      id: true,
      team_member_name: true
    }
  }
},
orderBy: {
  datetime: 'desc'
}
});

res.status(200).json({ meetings });
} catch (error) {
console.error('Get meetings error:', error);
res.status(500).json({ error: 'Failed to fetch meetings' });
}
});

// Create meeting for a deal
app.post('/api/deals/:dealId/meetings', authenticateToken, async (req, res) => {
try {
const { dealId } = req.params;
const { datetime, title, description, location } = req.body;

// Validate input
if (!datetime) {
return res.status(400).json({ error: 'Meeting date/time is required' });
}

// Check if user has permission to add meetings to this deal
const deal = await prisma.deal.findUnique({
where: { id: parseInt(dealId) },
include: {
  property: {
    select: { organisation_id: true }
  }
}
});

if (!deal) {
return res.status(404).json({ error: 'Deal not found' });
}

if (req.user.role !== 'superadmin' && deal.property.organisation_id !== req.user.organisation_id) {
return res.status(403).json({ error: 'You do not have permission to add meetings to this deal' });
}

// Create meeting
const meeting = await prisma.meeting.create({
data: {
  deal_id: parseInt(dealId),
  datetime: new Date(datetime),
  title,
  description,
  location,
  team_member_id: req.user.teamMember?.id || null
}
});

res.status(201).json(meeting);
} catch (error) {
console.error('Create meeting error:', error);
res.status(500).json({ error: 'Failed to create meeting' });
}
});

// TASKS ROUTES

// Get all tasks
app.get('/api/tasks', authenticateToken, async (req, res) => {
try {
const { status, assignedTo, dealId } = req.query;

// Build query filter
let where = {};

// Regular users can only see tasks from their organization's deals
if (req.user.role !== 'superadmin') {
where.deal = {
  property: {
    organisation_id: req.user.organisation_id
  }
};
}

// Add status filter if provided
if (status) {
where.status = status;
}

// Add assignedTo filter if provided
if (assignedTo) {
where.assigned_to = parseInt(assignedTo);
}

// Add deal filter if provided
if (dealId) {
where.deal_id = parseInt(dealId);
}

// Fetch tasks
const tasks = await prisma.task.findMany({
where,
include: {
  assignedTo: {
    select: {
      id: true,
      team_member_name: true
    }
  },
  deal: {
    select: {
      id: true,
      name: true
    }
  }
},
orderBy: [
  { due_date: 'asc' },
  { created_at: 'desc' }
]
});

res.status(200).json({ tasks });
} catch (error) {
console.error('Get tasks error:', error);
res.status(500).json({ error: 'Failed to fetch tasks' });
}
});

// Create task
app.post('/api/tasks', authenticateToken, async (req, res) => {
try {
const { title, description, due_date, status = 'Pending', assigned_to, deal_id } = req.body;

// Validate input
if (!title) {
return res.status(400).json({ error: 'Task title is required' });
}

// If deal_id is provided, check if user has access to it
if (deal_id) {
const deal = await prisma.deal.findUnique({
  where: { id: parseInt(deal_id) },
  include: {
    property: {
      select: { organisation_id: true }
    }
  }
});

if (!deal) {
  return res.status(404).json({ error: 'Deal not found' });
}

if (req.user.role !== 'superadmin' && deal.property.organisation_id !== req.user.organisation_id) {
  return res.status(403).json({ error: 'You do not have permission to create tasks for this deal' });
}
}

// Create task
const task = await prisma.task.create({
data: {
  title,
  description,
  due_date: due_date ? new Date(due_date) : null,
  status,
  assigned_to: assigned_to ? parseInt(assigned_to) : null,
  deal_id: deal_id ? parseInt(deal_id) : null
}
});

res.status(201).json(task);
} catch (error) {
console.error('Create task error:', error);
res.status(500).json({ error: 'Failed to create task' });
}
});

// Get task by ID
app.get('/api/tasks/:id', authenticateToken, async (req, res) => {
try {
const { id } = req.params;

const task = await prisma.task.findUnique({
where: { id: parseInt(id) },
include: {
  assignedTo: {
    select: {
      id: true,
      team_member_name: true
    }
  },
  deal: {
    select: {
      id: true,
      name: true,
      property: {
        select: {
          organisation_id: true
        }
      }
    }
  }
}
});

if (!task) {
return res.status(404).json({ error: 'Task not found' });
}

// Check if user has permission to view this task
if (task.deal && req.user.role !== 'superadmin' && task.deal.property.organisation_id !== req.user.organisation_id) {
return res.status(403).json({ error: 'You do not have permission to view this task' });
}

res.status(200).json({ task });
} catch (error) {
console.error('Get task error:', error);
res.status(500).json({ error: 'Failed to fetch task' });
}
});

// Update task
app.put('/api/tasks/:id', authenticateToken, async (req, res) => {
try {
const { id } = req.params;
const { title, description, due_date, status, assigned_to, deal_id } = req.body;

// Get the task to update
const existingTask = await prisma.task.findUnique({
where: { id: parseInt(id) },
include: {
  deal: {
    select: {
      property: {
        select: { organisation_id: true }
      }
    }
  }
}
});

if (!existingTask) {
return res.status(404).json({ error: 'Task not found' });
}

// Check if user has permission to update this task
if (existingTask.deal && req.user.role !== 'superadmin' && existingTask.deal.property.organisation_id !== req.user.organisation_id) {
return res.status(403).json({ error: 'You do not have permission to update this task' });
}

// If changing deal, check if user has access to the new deal
if (deal_id && (!existingTask.deal_id || deal_id !== existingTask.deal_id.toString())) {
const newDeal = await prisma.deal.findUnique({
  where: { id: parseInt(deal_id) },
  include: {
    property: {
      select: { organisation_id: true }
    }
  }
});

if (!newDeal) {
  return res.status(404).json({ error: 'Deal not found' });
}

if (req.user.role !== 'superadmin' && newDeal.property.organisation_id !== req.user.organisation_id) {
  return res.status(403).json({ error: 'You do not have permission to assign tasks to this deal' });
}
}

// Update task
const task = await prisma.task.update({
where: { id: parseInt(id) },
data: {
  title,
  description,
  due_date: due_date ? new Date(due_date) : null,
  status,
  assigned_to: assigned_to ? parseInt(assigned_to) : null,
  deal_id: deal_id ? parseInt(deal_id) : null
}
});

res.status(200).json({ task });
} catch (error) {
console.error('Update task error:', error);
res.status(500).json({ error: 'Failed to update task' });
}
});

// Delete task
app.delete('/api/tasks/:id', authenticateToken, async (req, res) => {
try {
const { id } = req.params;

// Get the task to delete
const existingTask = await prisma.task.findUnique({
where: { id: parseInt(id) },
include: {
  deal: {
    select: {
      property: {
        select: { organisation_id: true }
      }
    }
  }
}
});

if (!existingTask) {
return res.status(404).json({ error: 'Task not found' });
}

// Check if user has permission to delete this task
if (existingTask.deal && req.user.role !== 'superadmin' && existingTask.deal.property.organisation_id !== req.user.organisation_id) {
return res.status(403).json({ error: 'You do not have permission to delete this task' });
}

// Delete task
await prisma.task.delete({
where: { id: parseInt(id) }
});

res.status(200).json({ 
success: true, 
message: 'Task deleted successfully' 
});
} catch (error) {
console.error('Delete task error:', error);
res.status(500).json({ error: 'Failed to delete task' });
}
});

// DOCUMENTS ROUTES

// Get all documents
app.get('/api/documents', authenticateToken, async (req, res) => {
try {
const { deal_id, property_id } = req.query;

// Build query filter
let where = {};

// Regular users can only see documents from their organization
if (req.user.role !== 'superadmin') {
where.OR = [
  {
    deal: {
      property: {
        organisation_id: req.user.organisation_id
      }
    }
  },
  {
    property: {
      organisation_id: req.user.organisation_id
    }
  }
];
}

// Add deal filter if provided
if (deal_id) {
where.deal_id = parseInt(deal_id);
}

// Add property filter if provided
if (property_id) {
where.property_id = parseInt(property_id);
}

// Fetch documents
const documents = await prisma.document.findMany({
where,
include: {
  uploadedBy: {
    select: {
      id: true,
      team_member_name: true
    }
  },
  deal: {
    select: {
      id: true,
      name: true
    }
  },
  property: {
    select: {
      id: true,
      name: true
    }
  }
},
orderBy: {
  uploaded_at: 'desc'
}
});

res.status(200).json({ documents });
} catch (error) {
console.error('Get documents error:', error);
res.status(500).json({ error: 'Failed to fetch documents' });
}
});

// Create document
app.post('/api/documents', authenticateToken, async (req, res) => {
try {
const { title, file_url, file_type, deal_id, property_id } = req.body;

// Validate input
if (!title || !file_url) {
return res.status(400).json({ error: 'Title and file URL are required' });
}

// Check access to deal or property
if (deal_id) {
const deal = await prisma.deal.findUnique({
  where: { id: parseInt(deal_id) },
  include: {
    property: {
      select: { organisation_id: true }
    }
  }
});

if (!deal) {
  return res.status(404).json({ error: 'Deal not found' });
}

if (req.user.role !== 'superadmin' && deal.property.organisation_id !== req.user.organisation_id) {
  return res.status(403).json({ error: 'You do not have permission to add documents to this deal' });
}
}

if (property_id) {
const property = await prisma.property.findUnique({
  where: { id: parseInt(property_id) },
  select: { organisation_id: true }
});

if (!property) {
  return res.status(404).json({ error: 'Property not found' });
}

if (req.user.role !== 'superadmin' && property.organisation_id !== req.user.organisation_id) {
  return res.status(403).json({ error: 'You do not have permission to add documents to this property' });
}
}

// Create document
const document = await prisma.document.create({
data: {
  title,
  file_url,
  file_type,
  deal_id: deal_id ? parseInt(deal_id) : null,
  property_id: property_id ? parseInt(property_id) : null,
  uploaded_by: req.user.teamMember?.id || null
}
});

res.status(201).json(document);
} catch (error) {
console.error('Create document error:', error);
res.status(500).json({ error: 'Failed to create document' });
}
});

// Health check endpoint
app.get('/api/health', (req, res) => {
res.status(200).json({
status: 'ok',
timestamp: new Date().toISOString(),
env: process.env.NODE_ENV
});
});

// Add this to server.js

// TEAM INVITATION ROUTES

// Install brevo package
// npm install @getbrevo/brevo

const Brevo = require('@getbrevo/brevo');

// Invite a team member
app.post('/api/team/invite', authenticateToken, async (req, res) => {
  try {
    const { team_member_name, team_member_email_id, role } = req.body;
    
    // Validate input
    if (!team_member_name || !team_member_email_id) {
      return res.status(400).json({ error: 'Name and email are required' });
    }
    
    // Set organization from current user
    const organisation_id = req.user.organisation_id;
    
    if (!organisation_id) {
      return res.status(400).json({ error: 'You must be part of an organization to invite team members' });
    }
    
    // Check if user can invite team members for this organization
    if (req.user.role !== 'admin' && req.user.role !== 'superadmin') {
      return res.status(403).json({ error: 'You do not have permission to invite team members' });
    }
    
    // Check if email already exists in the organization
    const existingTeamMember = await prisma.teamMember.findFirst({
      where: {
        team_member_email_id,
        organisation_id
      }
    });
    
    if (existingTeamMember) {
      return res.status(400).json({ error: 'This email is already registered in your organization' });
    }
    
    // Get organization details for the email
    const organization = await prisma.organisation.findUnique({
      where: { id: organisation_id }
    });
    
    if (!organization) {
      return res.status(404).json({ error: 'Organization not found' });
    }
    
    // Create team member record
    const teamMember = await prisma.teamMember.create({
      data: {
        team_member_name,
        team_member_email_id,
        organisation_id
      }
    });
    
    // Generate invitation token (combine teamMember.id and organization.id)
    const invitationToken = jwt.sign(
      { 
        teamMemberId: teamMember.id, 
        organisationId: organisation_id,
        email: team_member_email_id,
        role: role || 'member',
        type: 'invitation'
      },
      JWT_SECRET,
      { expiresIn: '7d' }
    );
    
    // Create invitation URL
    const invitationUrl = `${process.env.FRONTEND_URL || 'http://localhost:3000'}/join?token=${invitationToken}`;
    
    // Send email via Brevo (formerly Sendinblue)
    const defaultClient = Brevo.ApiClient.instance;
    const apiKey = defaultClient.authentications['api-key'];
    apiKey.apiKey = process.env.BREVO_API_KEY;
    
    const apiInstance = new Brevo.TransactionalEmailsApi();
    const sender = {
      email: process.env.SENDER_EMAIL || 'noreply@yourdomain.com',
      name: process.env.SENDER_NAME || organization.organisation_name
    };
    
    const receivers = [
      {
        email: team_member_email_id,
        name: team_member_name
      }
    ];
    
    const emailParams = {
      sender,
      to: receivers,
      subject: `Invitation to join ${organization.organisation_name}`,
      htmlContent: `
        <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto; padding: 20px;">
          <h2>You've been invited to join ${organization.organisation_name}</h2>
          <p>Hello ${team_member_name},</p>
          <p>${req.user.email} has invited you to join their organization on CRM Dashboard.</p>
          <div style="margin: 30px 0;">
            <a href="${invitationUrl}" style="background-color: #4f46e5; color: white; padding: 12px 24px; text-decoration: none; border-radius: 4px; display: inline-block;">
              Accept Invitation
            </a>
          </div>
          <p>This invitation link will expire in 7 days.</p>
          <p>If you have any questions, please contact the person who invited you.</p>
        </div>
      `,
      params: {
        organizationName: organization.organisation_name,
        inviterEmail: req.user.email,
        inviteeEmail: team_member_email_id,
        inviteeName: team_member_name
      }
    };
    
    try {
      const result = await apiInstance.sendTransacEmail(emailParams);
      console.log('Email sent successfully:', result);
      
      // Save the invitation record
      await prisma.invitation.create({
        data: {
          email: team_member_email_id,
          token: invitationToken,
          team_member_id: teamMember.id,
          organisation_id,
          invited_by: req.user.id,
          status: 'pending',
          expires_at: new Date(Date.now() + 7 * 24 * 60 * 60 * 1000) // 7 days from now
        }
      });
      
      res.status(200).json({
        success: true,
        message: 'Invitation sent successfully',
        teamMember
      });
    } catch (emailError) {
      console.error('Error sending invitation email:', emailError);
      
      // Still create the team member, but inform about email failure
      res.status(207).json({
        success: true,
        emailSent: false,
        message: 'Team member created but failed to send invitation email',
        error: emailError.message,
        teamMember
      });
    }
  } catch (error) {
    console.error('Team invitation error:', error);
    res.status(500).json({ error: 'Failed to process invitation' });
  }
});

// Verify invitation token and create user account
app.post('/api/team/join', async (req, res) => {
  try {
    const { token, password } = req.body;
    
    if (!token || !password) {
      return res.status(400).json({ error: 'Token and password are required' });
    }
    
    // Verify token
    let decoded;
    try {
      decoded = jwt.verify(token, JWT_SECRET);
    } catch (tokenError) {
      return res.status(401).json({ error: 'Invalid or expired invitation token' });
    }
    
    // Check if it's an invitation token
    if (!decoded.type || decoded.type !== 'invitation') {
      return res.status(401).json({ error: 'Invalid token type' });
    }
    
    // Check if team member exists
    const teamMember = await prisma.teamMember.findFirst({
      where: {
        id: decoded.teamMemberId,
        organisation_id: decoded.organisationId,
        team_member_email_id: decoded.email
      }
    });
    
    if (!teamMember) {
      return res.status(404).json({ error: 'Team member not found' });
    }
    
    // Check if user already exists
    let user = await prisma.user.findUnique({
      where: { email: decoded.email }
    });
    
    if (user) {
      // User exists, check if already linked to this team member
      if (user.organisation_id === decoded.organisationId) {
        // Already in the organization, link to team member if not already
        if (!teamMember.user_id) {
          await prisma.teamMember.update({
            where: { id: teamMember.id },
            data: { user_id: user.id }
          });
        }
        
        // Generate token
        const token = jwt.sign(
          { 
            id: user.id, 
            email: user.email, 
            role: user.role,
            organisation_id: user.organisation_id
          },
          JWT_SECRET,
          { expiresIn: '7d' }
        );
        
        return res.status(200).json({
          success: true,
          message: 'Account already exists, logged in successfully',
          user: {
            id: user.id,
            email: user.email,
            role: user.role
          },
          token
        });
      } else {
        // User exists but in a different organization
        return res.status(409).json({ 
          error: 'Email already registered with a different organization',
          canLogin: true
        });
      }
    }
    
    // Hash password for new user
    const hashedPassword = await bcrypt.hash(password, 10);
    
    // Create new user
    user = await prisma.user.create({
      data: {
        email: decoded.email,
        password: hashedPassword,
        role: decoded.role,
        organisation_id: decoded.organisationId
      }
    });
    
    // Link user to team member
    await prisma.teamMember.update({
      where: { id: teamMember.id },
      data: { user_id: user.id }
    });
    
    // Update invitation status
    await prisma.invitation.updateMany({
      where: {
        team_member_id: teamMember.id,
        status: 'pending'
      },
      data: {
        status: 'accepted',
        accepted_at: new Date()
      }
    });
    
    // Generate token
    const userToken = jwt.sign(
      { 
        id: user.id, 
        email: user.email, 
        role: user.role,
        organisation_id: user.organisation_id
      },
      JWT_SECRET,
      { expiresIn: '7d' }
    );
    
    res.status(201).json({
      success: true,
      message: 'Account created and joined organization successfully',
      user: {
        id: user.id,
        email: user.email,
        role: user.role
      },
      token: userToken
    });
  } catch (error) {
    console.error('Join organization error:', error);
    res.status(500).json({ error: 'Failed to process join request' });
  }
});

// Add this to server.js

// Verify invitation token
app.post('/api/team/verify-token', async (req, res) => {
  try {
    const { token } = req.body;
    
    if (!token) {
      return res.status(400).json({ error: 'Token is required' });
    }
    
    // Verify token
    let decoded;
    try {
      decoded = jwt.verify(token, JWT_SECRET);
    } catch (tokenError) {
      return res.status(401).json({ error: 'Invalid or expired invitation token' });
    }
    
    // Check if it's an invitation token
    if (!decoded.type || decoded.type !== 'invitation') {
      return res.status(401).json({ error: 'Invalid token type' });
    }
    
    // Check if team member exists
    const teamMember = await prisma.teamMember.findFirst({
      where: {
        id: decoded.teamMemberId,
        organisation_id: decoded.organisationId,
        team_member_email_id: decoded.email
      },
      include: {
        organisation: {
          select: {
            organisation_name: true
          }
        }
      }
    });
    
    if (!teamMember) {
      return res.status(404).json({ error: 'Team member not found' });
    }
    
    // Check if user already exists and is linked to team member
    if (teamMember.user_id) {
      return res.status(400).json({ error: 'This invitation has already been accepted' });
    }
    
    // Check if invitation exists and is still pending
    const invitation = await prisma.invitation.findFirst({
      where: {
        team_member_id: teamMember.id,
        status: 'pending',
        expires_at: {
          gte: new Date()
        }
      }
    });
    
    if (!invitation) {
      return res.status(400).json({ error: 'Invitation not found or has expired' });
    }
    
    // Return token info
    res.status(200).json({
      success: true,
      tokenInfo: {
        name: teamMember.team_member_name,
        email: teamMember.team_member_email_id,
        organizationName: teamMember.organisation.organisation_name,
        role: decoded.role
      }
    });
  } catch (error) {
    console.error('Verify invitation token error:', error);
    res.status(500).json({ error: 'Failed to verify invitation token' });
  }
});

// Resend invitation
app.post('/api/team/invite/resend', authenticateToken, async (req, res) => {
  try {
    const { team_member_id } = req.body;
    
    // Validate input
    if (!team_member_id) {
      return res.status(400).json({ error: 'Team member ID is required' });
    }
    
    // Get team member details
    const teamMember = await prisma.teamMember.findUnique({
      where: { id: parseInt(team_member_id) },
      include: {
        organisation: true,
        user: {
          select: {
            id: true
          }
        }
      }
    });
    
    if (!teamMember) {
      return res.status(404).json({ error: 'Team member not found' });
    }
    
    // Check if user is authorized to resend invitation
    if (req.user.role !== 'admin' && req.user.role !== 'superadmin' && req.user.organisation_id !== teamMember.organisation_id) {
      return res.status(403).json({ error: 'You do not have permission to resend invitations for this organization' });
    }
    
    // Check if team member already has a user account
    if (teamMember.user) {
      return res.status(400).json({ error: 'This team member has already accepted the invitation' });
    }
    
    // Generate new invitation token
    const invitationToken = jwt.sign(
      { 
        teamMemberId: teamMember.id, 
        organisationId: teamMember.organisation_id,
        email: teamMember.team_member_email_id,
        role: 'member', // Default role
        type: 'invitation'
      },
      JWT_SECRET,
      { expiresIn: '7d' }
    );
    
    // Create invitation URL
    const invitationUrl = `${process.env.FRONTEND_URL || 'http://localhost:3000'}/join?token=${invitationToken}`;
    
    // Update or create invitation record
    await prisma.invitation.updateMany({
      where: {
        team_member_id: teamMember.id,
        status: 'pending'
      },
      data: {
        status: 'expired'
      }
    });
    
    await prisma.invitation.create({
      data: {
        email: teamMember.team_member_email_id,
        token: invitationToken,
        team_member_id: teamMember.id,
        organisation_id: teamMember.organisation_id,
        invited_by: req.user.id,
        status: 'pending',
        expires_at: new Date(Date.now() + 7 * 24 * 60 * 60 * 1000) // 7 days from now
      }
    });
    
    // Send email via Brevo
    const defaultClient = Brevo.ApiClient.instance;
    const apiKey = defaultClient.authentications['api-key'];
    apiKey.apiKey = process.env.BREVO_API_KEY;
    
    const apiInstance = new Brevo.TransactionalEmailsApi();
    const sender = {
      email: process.env.SENDER_EMAIL || 'noreply@yourdomain.com',
      name: process.env.SENDER_NAME || teamMember.organisation.organisation_name
    };
    
    const receivers = [
      {
        email: teamMember.team_member_email_id,
        name: teamMember.team_member_name
      }
    ];
    
    const emailParams = {
      sender,
      to: receivers,
      subject: `Invitation Reminder: Join ${teamMember.organisation.organisation_name}`,
      htmlContent: `
        <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto; padding: 20px;">
          <h2>Reminder: You've been invited to join ${teamMember.organisation.organisation_name}</h2>
          <p>Hello ${teamMember.team_member_name},</p>
          <p>${req.user.email} has invited you to join their organization on CRM Dashboard. We noticed you haven't accepted the invitation yet.</p>
          <div style="margin: 30px 0;">
            <a href="${invitationUrl}" style="background-color: #4f46e5; color: white; padding: 12px 24px; text-decoration: none; border-radius: 4px; display: inline-block;">
              Accept Invitation
            </a>
          </div>
          <p>This invitation link will expire in 7 days.</p>
          <p>If you have any questions, please contact the person who invited you.</p>
        </div>
      `,
      params: {
        organizationName: teamMember.organisation.organisation_name,
        inviterEmail: req.user.email,
        inviteeName: teamMember.team_member_name
      }
    };
    
    try {
      const result = await apiInstance.sendTransacEmail(emailParams);
      console.log('Reminder email sent successfully:', result);
      
      res.status(200).json({
        success: true,
        message: 'Invitation resent successfully'
      });
    } catch (emailError) {
      console.error('Error sending invitation reminder email:', emailError);
      
      res.status(207).json({
        success: true,
        emailSent: false,
        message: 'Failed to send invitation email',
        error: emailError.message
      });
    }
  } catch (error) {
    console.error('Resend invitation error:', error);
    res.status(500).json({ error: 'Failed to resend invitation' });
  }
});

// Start server
app.listen(PORT, () => {
console.log(`Server running on port ${PORT}`);
});

module.exports = app;
