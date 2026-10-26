$currentUser = $request->user();
Context::add('user', $request->user());
$request->attributes->set('tenant', $tenantId);
$this->user = $request->user();
// self::$currentUser = $request->user();
private $currentUser;
public function getUser() { return $this->user; }
