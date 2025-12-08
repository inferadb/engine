use tonic::{Request, Response, Status};

use super::{
    InferadbServiceImpl,
    proto::{HealthRequest, HealthResponse},
};

pub async fn health(
    _service: &InferadbServiceImpl,
    _request: Request<HealthRequest>,
) -> Result<Response<HealthResponse>, Status> {
    Ok(Response::new(HealthResponse {
        status: "healthy".to_string(),
        service: "inferadb-engine".to_string(),
    }))
}
