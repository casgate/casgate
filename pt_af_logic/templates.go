package pt_af_logic

const builtInAdminTmpl = `
<p>[PT LM] Partner '{{ .Organization.Name }}' subscription '{{ .Subscription.Name }}' updated: {{ .OldStatus }} -> {{ .NewStatus }}</p>
<p>Actor: {{ .Actor.Name }} </p>
`

const partnerSubscriptionTmpl = `
<p>Организация: {{ .Organization.Name }}</p>
<p>Партнёр: {{ .PartnerManager.Name }}</p>
<p>Клиент: {{ .PartnerUser.Name }}</p>
<p>Подписка: {{ .Subscription.Name }}</p>
<p>Тарифный план: {{ .Subscription.Plan }}</p>
<p>Дата начала: {{ .Subscription.StartDate }}</p>
<p>Дата окончания: {{ .Subscription.EndDate }}</p>
<p>Комментарий: {{ .Subscription.Description }}</p>
<p>Статус: {{ .OldStatus }} -> {{ .NewStatus }}</p>
<p>Автор изменения: {{ .Actor.Name }}</p>
`
