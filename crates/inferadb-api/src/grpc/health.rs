use tonic::{Request, Response, Status};

use super::{
    InferaServiceImpl,
    proto::{HealthRequest, HealthResponse},
};

pub async fn health(
    _service: &InferaServiceImpl,
    _request: Request<HealthRequest>,
) -> Result<Response<HealthResponse>, Status> {
    Ok(Response::new(HealthResponse {
        status: "healthy".to_string(),
        service: "inferadb".to_string(),
    }))
}
