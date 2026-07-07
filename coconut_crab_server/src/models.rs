#[derive(Debug, toasty::Model)]
pub struct Victim {
    #[key]
    pub(crate) id: String,
    pub(crate) hostname: String,
    pub(crate) key: String,
    pub(crate) code: String,
    pub(crate) upload_time: i64,
    pub(crate) complete: bool,
}
