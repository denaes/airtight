<div>{{ $userInput }}</div>
<div>{!! csrf_field() !!}</div>
<span>{!! $slot !!}</span>
<svg>{!! $icon !!}</svg>
<p>{{ $comment->body }}</p>
