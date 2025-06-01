export const prerender = false;
import { createClient } from "@supabase/supabase-js";
import { generateSecretKeyHash, generateCode, decryptCode, verifyCode, extractEmailFromCode } from "../../lib/generateCodes.js";

const email_secret = generateSecretKeyHash(import.meta.env.EMAIL_SECRET);

export async function POST({ request }) {
  const origin = request.headers.get('origin');
  const requestUrl = new URL(request.url);

  const getRootDomain = (hostname) => {
    const parts = hostname.split('.');
    return parts.slice(-2).join('.'); 
  };

  const apiRootDomain = getRootDomain(requestUrl.hostname);
  const originRootDomain = origin ? getRootDomain(new URL(origin).hostname) : null;
    
  if (origin && originRootDomain !== apiRootDomain) {
    return new Response(JSON.stringify({ 
      error: 'forbidden',
      message: 'Access Denied'
    }), {
      status: 403,
      headers: { 
        'Content-Type': 'application/json',
        'Vary': 'Origin'
      }
    });
  }

  const contentType = request.headers.get('content-type') || '';
  if (!contentType.includes('multipart/form-data')) {
    return new Response(JSON.stringify({ 
      error: 'Invalid content type',
      message: 'Expected form data'
    }), {
      status: 415,
      headers: { 'Content-Type': 'application/json' }
    });
  }

  try {
    let requestBody;
    try {
      requestBody = await request.formData();
    } catch (e) {
      return new Response(JSON.stringify({ 
        error: 'Invalid form data',
        message: 'The request body contains invalid form data'
      }), {
        status: 400,
        headers: { 'Content-Type': 'application/json' }
      });
    }

    const title = requestBody.get('title');
    const visibility = requestBody.get('visibility');
    const emailCode = requestBody.get('emailCode');
    const password = requestBody.get('password');

    if (!title || !visibility || !emailCode || !pdf) {
      return new Response(JSON.stringify({ 
        error: 'Missing required fields',
        message: 'Missing required fields in form data'
      }), {
        status: 400,
        headers: { 'Content-Type': 'application/json' }
      });
    }

    if (!verifyCode(email_secret, emailCode)) {
      return new Response(JSON.stringify({ 
        error: 'Invalid email code',
        message: 'Invalid email code. Redirecting to login page...',
        redirect: '/login'
      }), {
        status: 403,
        headers: { 'Content-Type': 'application/json' }
      });
    }
  
    const email = extractEmailFromCode(emailCode);

    const supabase = createClient(
      import.meta.env.SUPABASE_URL,
      import.meta.env.SUPABASE_SERVICE_ROLE_KEY
    );

    const { data: profile, error: profileError } = await supabase
      .from("profiles")
      .select("email") 
      .eq("email", email)
      .maybeSingle();

    if (profileError) {
      return new Response(JSON.stringify({
        error: 'Profile lookup failed',
        message: profileError.message
      }), {
        status: 500,
        headers: { 'Content-Type': 'application/json' }
      });
    }

    if (!profile) {
      return new Response(JSON.stringify({
        error: 'Authentication failed',
        message: 'No account found with this email address. Redirecting to login page...'
      }), {
        status: 403,
        headers: { 'Content-Type': 'application/json' }
      });
    }

    // Code limits functionality
    // Integrate AI part
    // Supabase logic add
      
    return new Response(JSON.stringify({ 
      message: 'Successfully created deck! Redirecting to your decks...',
    }), {
      status: 200,
      headers: { 
        'Content-Type': 'application/json',
        ...(origin && { 'Access-Control-Allow-Origin': origin }),
        'Vary': 'Origin'
      }
    });

  } catch (error) {
    console.error(error);
    
    return new Response(JSON.stringify({ 
      message: error.message,
    }), {
      status: 500,
      headers: { 
        'Content-Type': 'application/json',
        ...(origin && { 'Access-Control-Allow-Origin': origin })
      }
    });
  }
}

export async function OPTIONS({ request }) {
  const origin = request.headers.get('origin');
  const requestUrl = new URL(request.url);

  const getRootDomain = (hostname) => {
    const parts = hostname.split('.');
    return parts.slice(-2).join('.'); 
  };

  const apiRootDomain = getRootDomain(requestUrl.hostname);
  const originRootDomain = origin ? getRootDomain(new URL(origin).hostname) : null;

  const isAllowedOrigin = originRootDomain === apiRootDomain;
  
  return new Response(null, {
    status: isAllowedOrigin ? 204 : 403,
    headers: {
      'Access-Control-Allow-Origin': isAllowedOrigin ? origin : '',
      'Access-Control-Allow-Methods': 'POST, OPTIONS',
      'Access-Control-Allow-Headers': 'Content-Type, Authorization',
      'Access-Control-Max-Age': '86400', 
      'Access-Control-Allow-Credentials': 'true',
      'Vary': 'Origin, Access-Control-Request-Headers',
      ...(!isAllowedOrigin && {
        'Content-Type': 'text/plain',
        'Content-Length': '0'
      })
    }
  });
}
