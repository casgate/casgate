package pt_af_logic

const builtInAdminTmpl = `
<p>PT LMP] Partner '{{ .Organization.Name }}' subscription '{{ .Subscription.Name }}' updated: {{ .OldStatus }} -> {{ .NewStatus }}</p>
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

const partnerCreateAccountsSubjTmpl = `[PT LMP] Accounts for {{ .ClientName }}`

const partnerCreateAccountsBodyTmpl = `
<p>В PT AF создано изолированное пространство для клиента <a href="{{ .ClientURL }}">{{ .ClientDisplayName }}</a>.</p>

<p>Строка подключения для агента: {{ .ConnectionString }}</p>

<p>Ссылка для входа: {{ .PTAFLoginLink }}<br>
При первом входе потребуется сменить пароль.</p>

<p>Сервисная учётная запись<br>
Логин: {{ .ServiceUserName }}<br>
Временный пароль: {{ .ServiceUserPwd }}</p>

<p>Пользовательская учётная запись<br>
Логин: {{ .UserROName }}<br>
Временный пароль: {{ .UserROPwd }}</p>
`

const partnerCreatedSubjTmpl = `[PT LMP] Partner {{ .PartnerName }} registered`

const partnerCreatedBodyTmpl = `
<p>Партнёр <a href="{{ .PartnerURL }}">{{ .PartnerDisplayName }}</a> зарегистрировался на портале.<br>
Для подтверждения регистрации включите опцию "Is admin" и отключите "Is forbidden" в аккаунте партнёра: <a href="{{ .PartnerAccount }}">{{ .PartnerUserName }}</a>.</p>
`

const partnerConfirmedBodyTmpl = `
<p>Ваша регистрация на портале подтверждена.</p>
<p>Логин: {{ .PartnerUserName }}<br>
Ссылка для входа на портал: <a href="{{ .PartnerLoginURL }}">{{ .PartnerLoginURL }}</a></p>
`
