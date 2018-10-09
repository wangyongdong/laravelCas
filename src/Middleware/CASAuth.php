<?php
namespace Cas\Middleware;

use Closure;
use Illuminate\Contracts\Auth\Guard;

class CASAuth
{

    /**
     * @var Guard
     */
    protected $auth;

    /**
     * @var \Illuminate\Foundation\Application|mixed
     */
    protected $cas;

    public function __construct(Guard $auth)
    {
        $this->auth = $auth;
        $this->cas = app('cas');
    }

    /**
     * Handle an incoming request.
     *
     * @param $request
     * @param Closure $next
     * @return \Illuminate\Contracts\Routing\ResponseFactory|\Illuminate\Http\Response|mixed|\Symfony\Component\HttpFoundation\Response|void
     */
    public function handle($request, Closure $next)
    {
        if($this->cas->checkAuthentication())
        {
            $request->offsetSet('user', $this->cas->user());
            // 存到 session...
            session(['userid' => $this->cas->user()]);
        } else {
            if ($request->ajax() || $request->wantsJson()) {
                return response('Unauthorized.', 401);
            }
            $this->cas->authenticate();
        }

        return $next($request);
    }
}
