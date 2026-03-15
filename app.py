from fastapi import FastAPI,Request,Form
from fastapi.templating import Jinja2Templates
from fastapi.responses import JSONResponse,FileResponse
from fastapi.middleware.httpsredirect import HTTPSRedirectMiddleware
from starlette.middleware.base import BaseHTTPMiddleware
from secure import scan_api
from report import generate_pdf
import uvicorn
import traceback
app=FastAPI()
scan_results=None
templates = Jinja2Templates(directory="templates")


class SecurityHeadersMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):
        response = await call_next(request)
        response.headers["X-Frame-Options"]              = "SAMEORIGIN"
        response.headers["X-Content-Type-Options"]       = "nosniff"
        response.headers["X-XSS-Protection"]             = "1; mode=block"
        response.headers["Strict-Transport-Security"]    = "max-age=63072000; includeSubDomains; preload"
        response.headers["Referrer-Policy"]              = "strict-origin-when-cross-origin"
        response.headers["Permissions-Policy"]           = "geolocation=(), microphone=(), camera=()"
        response.headers["Content-Security-Policy"]      = "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'"
        response.headers["Cache-Control"]                = "no-store"
        response.headers["X-Permitted-Cross-Domain-Policies"] = "none"
        return response

app.add_middleware(SecurityHeadersMiddleware)
@app.get('/')
async def index(request:Request):
    
    return templates.TemplateResponse("index.html", {"request": request, "scan_results": None})
@app.post('/scanning')
async def scanning(request:Request,endpoint: str = Form(...)):
    try:
        global scan_results
        scan_results=scan_api(endpoint)

        return templates.TemplateResponse('index.html',{'request':request,'scan_results':scan_results})
    except Exception as e:
        return templates.TemplateResponse('index.html',{'msg':str(e)})

@app.get("/download")
async def download():
    if scan_results is None:
        return JSONResponse({'msg': 'No scan has been run yet'}, status_code=400)
    try:
        generate_pdf(scan_results)
        print(traceback.format_exc())
        return FileResponse("report.pdf", filename="report.pdf")
    except Exception as e:
        return JSONResponse({'msg': str(e)}, status_code=500)


if __name__=="__main__":
    uvicorn.run(app, port=5012)