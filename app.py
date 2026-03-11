from fastapi import FastAPI,Request,Form
from fastapi.templating import Jinja2Templates
from fastapi.responses import JSONResponse,FileResponse
from secure import scan_api
from report import generate_pdf
import uvicorn
app=FastAPI()
scan_results=None
templates = Jinja2Templates(directory="templates")
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

@app.post("/download")
async def download():
    
    try:
        generate_pdf(scan_results)
        return FileResponse("report.pdf", as_attachment=True)

    except Exception  as e:
        return JSONResponse({'msg':str(e)}),500



if __name__=="__main__":
    uvicorn.run(app, port=5012)